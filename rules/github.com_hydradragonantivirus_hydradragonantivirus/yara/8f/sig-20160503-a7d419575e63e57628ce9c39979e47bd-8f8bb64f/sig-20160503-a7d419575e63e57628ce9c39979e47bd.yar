rule sig_20160503_a7d419575e63e57628ce9c39979e47bd {
  meta:
    description = "datamaliciousorder - file 20160503_a7d419575e63e57628ce9c39979e47bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ffbec7e7e06acbef8e40055d1df23a25ea27ed75ece772fe9acbcce3dabd3f9"

  strings:
    $s1  = "eval((function(){var z=[87,66,72,86,90,70,82,74,65,76,89,80,60,71,88,75,85,81,94,79];var y=[];for(var q=0;q<z.length;q++)y[z[q]]" ascii
    $s2  = "m@t(true,0,0)}else {Wr@i@gi@x=([(6917,3268,5022,8967,4200,0),@gScript])[(149WY5448,B ,762We7,527W}15,1177,36Wx083,1W_ @mrEhm@z=@" ascii
    $s3  = "ar q=0;q<h.length;q++)r=r.split(v+g.charAt(q)).join(String.fromCharCode(h[q]));return r.split(v+'!').join(v);})('function @g@q@o" ascii
    $s4  = "=38093Ww7===\"xkwf\"){}WN@qb@mtMW=iCscvl(p@v@kW]Muir@h=[rS@pD@wa(),@kWG,t@hS(),\"m\",WM),\"h\",huk(),@kWG,WM),t@hS(),\"d\",t@jqb" ascii
    $s5  = "witch(falseWW~W6u@lrq~5,1103,2833,8357,2)~itch(4WWtrue:v~3,9649,3585,6895,3)~(4991,8846,5788,708~var el@m@wiNEW^~@oz@o@q@u\"W[;v" ascii
    $s6  = "55};W2xakjW|j@wrWbxakjWKTEDMWp};bWBuuhhz=\"cNMd@u\";;W`W\\\\\"\"W`@q@nmEf=zo@qtrgMe.length;while(Wg@s@q@nmEf-(79W)W]sTf@o@qWhW\"" ascii
    $s7  = "eval((function(){var z=[87,66,72,86,90,70,82,74,65,76,89,80,60,71,88,75,85,81,94,79];var y=[];for(var q=0;q<z.length;q++)y[z[q]]" ascii
    $s8  = "(j+1)-32;m=j;j++;}else if(p==96){n=94*(z.length-32+k.charCodeAt(j+1))+k.charCodeAt(j+2)-32;m=j;j+=2;}else{continue;}if(u==null)u" ascii
    $s9  = "2,3289,6020,736,5200,200)){switch(461WW223Waf@h@m@h=WdW:0Wv1=WSWJ;W`@hyw=W<pjp);swW*W1W/aW7W W4W.W5W-;W`@pl@hbv=WoWO16Wq5020Wy51" ascii
    $s10 = "@lwi@zN@v~\"WN~)WN~@vyI@pc()~trueWa~==Wd){~}W[;~==0W]~@iCscvl((~p@tb@l@p(~;return ~[pEwg(\"0~=pEwg(\"0~;switch(~WV@~=Wp){~=Wg+(~" ascii
    $s11 = "WY5448,B ,762We7,527W}15,1177,36Wx083,1),@jn@jh@w][(149WY5448,B ,762We7,527W}15,1177,36Wx083,1)]()}};cc@u@i(\"a@zoD@lb\")}catch(" ascii
    $s12 = "f(@jExx@x=WSv~ase@t=trueW[;~ar @jExx@xWXi~break;case 0Wa~MoCp@jn@rWO~@j@n@iEm@r@k=\"@g~ar Dgp@r=39785;~@vq(zo@qtrgMe,~r amq@zq=4" ascii
    $s13 = "~()W`~){case ~=Wd;~1,1111,~==1){};~;break}~sIwN@k=~){Wr~Wp;~)];var~;Wr~:Wr~\"Ww~\":var~false~2,473~)Ww~u@lrq~=(667~05200~NgC@l~4" ascii
    $s14 = "961~;@hywWO0~3==\"xIvhD\"){v~;break;case ~)WC(~@ktvm@t@p@j(~W@@~)+TT@rd@v((~(1===0){};b~}function ~@pDn@kpd@r~reak}W`~)+@iCscvl(" ascii
    $s15 = "k@xc){}~}W:1:var ~reak;case Wd:if(~2,8141,5128,8447,0)~ar E@uaE@tN@t=24521~switch(5WW1:if~887,20,8478,2485,1)~break;case Wd:va~s" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}