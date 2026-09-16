rule sig_20160503_983fa78c10725da46a3ecc4eb038ff86 {
  meta:
    description = "datamaliciousorder - file 20160503_983fa78c10725da46a3ecc4eb038ff86.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a952222d999884fd4239e327369e079a8e1808b589559fac61a537b062268de"

  strings:
    $s1  = "eval((function(){var j=[89,85,81,71,75,66,79,87,80,74,90,94,72,70,60,76,65,86,82,88];var s=[];for(var p=0;p<j.length;p++)s[j[p]]" ascii
    $s2  = "ar p=0;p<g.length;p++)e=e.split(l+v.charAt(p)).join(String.fromCharCode(g[p]));return e.split(l+'!').join(l);})('function @sldoy" ascii
    $s3  = "9,~=t@t@k@l(~@kU8ab)~;break};~;return ~Yn@~;Yo~==Y{~l@xS@vv(~5,9306,3~Yu5~31,8417,~333,5287~(Yx~)U* ~()U!~U)h(~\"U\"@~(EtszhS~;;" ascii
    $s4  = "@y@zU#gS@iq===429){Y?Itr=998U!zyqvhtYzY8i@gj@xlp@kYptb@y=\"x@pIx@gl\"Ybreturn true}try{if(@pyqbf(252)!=1){@sldoyS(U%)}else {U,ty" ascii
    $s5  = "(r+1)-32;m=r;r++;}else if(u==96){a=94*(j.length-32+h.charCodeAt(r+1))+h.charCodeAt(r+2)-32;m=r;r+=2;}else{continue;}if(z==null)z" ascii
    $s6  = "eval((function(){var j=[89,85,81,71,75,66,79,87,80,74,90,94,72,70,60,76,65,86,82,88];var s=[];for(var p=0;p<j.length;p++)s[j[p]]" ascii
    $s7  = "el@s=\"n@wTa@hU7Y0I@t@zIu@m=\"iukuU7Y z@swv@j=35488YB\"wCqe@zYpn@z@v=67741YbU2zv@wU$YrY|=\"\"U!cmETse=nd@mq@mU8D.length;while(@k" ascii
    $s8  = "U\"~}function ~Yz;if(~ueYmt~Yc@~U$;if(~=DpIyi(\"0~=Yz){~[DpIyi(\"0~@kU8ab+~\"Yc~)Yc~}Yb~))+U\\'(~==0Yx~)Ye~Ym1:~r@glh@w()~Yj4~47" ascii
    $s9  = "~4,8997,9721,6903,0)~ak;case trueU57==~if(@x@n@w@t@yU+}~@lar=18169YX~S@g@iy@m=79366U4S~yu@t@ieE\"Yetr~nMEw=59993U4nMEw=~@g@iy@mY" ascii
    $s10 = "var~rue:if(7=Yfva~=zcz(nd@mq@mU8D,~break}U!So@wg=\"~94,8720,1390,1634,~,7135,6142,9585,2)~eak;case trueU\"~vYA;var~r @qTe@vI@lv=" ascii
    $s11 = "40,1617,4834~YXvar ~YE@~@mtp===174){}~;break;case ~))+Yg(~YJy~yrw@yU#@v~YM@~Ifvy@zz@m10~2261,7118,3~,Y_2~v@mtp=\"bul@~oNYT~ fals" ascii
    $s12 = ",1),x@qwNtcy][(4469,9556,4532,9144,1)]()}}U4N@gy@l@xd(0,1)YSU,k@vj@z=\"@shjiy\"}}catch(cMhpj){}~eak;caseYL~Y90:var ~h(7Ymfalse:v" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}