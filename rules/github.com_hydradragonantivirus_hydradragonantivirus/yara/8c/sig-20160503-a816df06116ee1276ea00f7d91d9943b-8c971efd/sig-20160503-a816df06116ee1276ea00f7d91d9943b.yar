rule sig_20160503_a816df06116ee1276ea00f7d91d9943b {
  meta:
    description = "datamaliciousorder - file 20160503_a816df06116ee1276ea00f7d91d9943b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecd2ecf854fff0dc96668cd9d9c744fbff46477b5942d089c5c493f6d942b633"

  strings:
    $s1  = "eval((function(){var a=[88,87,65,75,80,76,85,72,71,81,74,90,86,82,94,60,79,89,66,70];var k=[];for(var g=0;g<a.length;g++)k[a[g]]" ascii
    $s2  = "ar g=0;g<j.length;g++)h=h.split(e+o.charAt(g)).join(String.fromCharCode(j[g]));return h.split(e+'!').join(e);})('function bvu@qM" ascii
    $s3  = "7Xgqn@t=23501;;XoXD\"\"Xola@p=i@w@m.length;while(@jXd@vla@p-XXX2X32)XfNoly@i=XwX\\'X&X\"Xon@r@i@y@zlXCXUX1X.Xgy@t@rXGn@r@i@y@zl)" ascii
    $s4  = "eval((function(){var a=[88,87,65,75,80,76,85,72,71,81,74,90,86,82,94,60,79,89,66,70];var k=[];for(var g=0;g<a.length;g++)k[a[g]]" ascii
    $s5  = "\"@iXTy@yjT@teXAr@m@wv(){switch(1X_XzXi@gsEhvXj;X0XrsN@z=\"@n@zwaN\"Xh}Xoms@z@l=47217XonqCv@l@o@o=\"q@w@tdt\";;XgxT@hXvDy@h=\"o" ascii
    $s6  = ";;;~=cm@ouq(\"0~[cm@ouq(\"0~))+fMCxj((~Xj;if(~302:Xri@~@tpamx@lqh~XZ@~\"XZ~(4906,379~=Xj){~E@oiavh@l~(5365,143~xN@p@i@n=~;return" ascii
    $s7  = "(s+1)-32;m=s;s++;}else if(f==96){d=94*(a.length-32+z.charCodeAt(s+1))+z.charCodeAt(s+2)-32;m=s;s+=2;}else{continue;}if(x==null)x" ascii
    $s8  = "Xf@jSi=56963XslS@z===\"udk@o@lsz\"XfrsExg@q=71712}}try{if(y@s@md@zXv(Xze)==0){wh@l@s@zje(0,367)};bvu@qMdE(\"@t@pMgoCx\",0,true)X" ascii
    $s9  = "@im@k@r@j~XH\"~\"XsxN@p@i@~XK@~))+Xe(~=@jXd+~o@ruxnv@to=~4191,6385,3~652Xb4~=bxd(i@w@m,~\"q@kd@iIa@y~st=78372;br~eXN~}function ~" ascii
    $s10 = "ruXirdoXqXh;case 243:XrDki=\"lMg@h\";brX b@wb=\"g@hInd@rq\"Xsb@wb==181XfS@z@idN@zo=45463X<0W 5===\"@y@xggn\"XfM@y@j@qj=\"NiofcMb" ascii
    $s11 = "204Xs~@nnt@qzqy=78400;b~Cs@n=trueXh};~ar s@s@gXj;br~X14~4602,3558,5061,1)~meNDDwrXN~break;case true:~,2100,3090,7495,~3,6918,219" ascii
    $s12 = "@xhMlDD=bxdX4+XXX2X32))Xgq@k@i@ijo=bxdX4);XD@q@k@i@ijo+@y@t@r+Mo@xhMlDDXovMp@r@roz=bxdX4)X\\\\3X_0:XrbMe@q@p=\"bMgh\"Xh;case 1:X" ascii
    $s13 = "5,2211~,8471,3871,9967,~(i@w@m,@jXd~jX;n~nejiyXj};bre~ak}Xs1===1){};~reak;case 622:v~witch(5X_~X>D~D@kk\"Xf@gb~}Xh;case ~X@n~n==" ascii
    $s14 = "lsXi~X&3~3,9861,6386,9434,0)~switch(trueX_~Xh;case 0:var ~X\\'3~3005,7352,6299,728~9,6433,6366,8546,~itt@kgD==\"kDk\"){}~itt@kgD" ascii
    $s15 = "50:Xr~;switch(~()Xo~(Xf~){case ~Ibkmq@t~mku@qv(~5,7485,~Xn5~E@h@oTx~E@k@wb(~){Xr~Xo@~;break~e:Xr~=Xze~174,11~191,69~)];var~09,65" ascii
    $s16 = "3,8X}4563,7950,W#,2130,1983,7165,7400,1),@rxNl][(3W\"5213,8X}4563,7950,W#,2130,1983,7165,7400,1)]()}}catch(@nlaw@r){}~eak;case f" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}