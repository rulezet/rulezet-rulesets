rule sig_20160503_ba6e2828dc4be17705d6ff8876f96fbe {
  meta:
    description = "datamaliciousorder - file 20160503_ba6e2828dc4be17705d6ff8876f96fbe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ea485944cb05af0ecc4cf97e0c4d019beaab2cb38d7350392e6e37f7ca4da80"

  strings:
    $s1  = "eval((function(){var l=[88,75,60,74,76,94,72,90,70,66,80,71,82,87,65,81,79,89,85,86];var t=[];for(var p=0;p<l.length;p++)t[l[p]]" ascii
    $s2  = "ar p=0;p<n.length;p++)q=q.split(u+i.charAt(p)).join(String.fromCharCode(n[p]));return q.split(u+'!').join(u);})('function @t@jav" ascii
    $s3  = "nIXI~XE@~(1870,948,9~}XQ;;~=gDr@s@q@z(~@oSj@jC@kp=~}function ~=XS+~wpwx@ty===~\"XL~[XN~trueX^~)XR~;return ~))+Xq(~h@rcq(\"0~(XZ@" ascii
    $s4  = "I17013008Xk@xq@w@p@kg,(3114,8601,4036,4569,0))};EE@y(X9,wvi)XEIa@rE(){switch(0XV1X^Dkl@q@x=61182XeX5 M@ugp@o@rh=\"@kcl@vhdr\"Xek" ascii
    $s5  = "eval((function(){var l=[88,75,60,74,76,94,72,90,70,66,80,71,82,87,65,81,79,89,85,86];var t=[];for(var p=0;p<l.length;p++)t[l[p]]" ascii
    $s6  = "(a+1)-32;d=a;a++;}else if(h==96){f=94*(l.length-32+o.charCodeAt(a+1))+o.charCodeAt(a+2)-32;d=a;a+=2;}else{continue;}if(j==null)j" ascii
    $s7  = "v.length;while(XS@iSnkcjps-X&XZ@gqh@k@hX(X]lotk@j@xo@gXF(XlX%X]@y@v@gEsI@y=X>lotk@j@xo@g)X]@phm=vTX\\'+X&)X]rC@t@qzm=vTX\\');XDr" ascii
    $s8  = "qlwe@k(~Xek};~;switch(~x@xu@oen~){}X]~()X]~){case ~iNz@rN(~ztwpMua~Sn@xl10~){Xt~=fK(~465:va~;Xt~:Xt~=true~)Xi~achfg~\"Xi~8582,~@" ascii
    $s9  = ",8283,8067,8754,5X`qpI){[(997Xo7,240,1XhXp1),@kxIC][(997Xo7,240,1XhXp1)]()}}}catch(qhc@j){}~X$v~XtbEE@y@jei=1322;~X;1:var ~f(7==" ascii
    $s10 = "X81~k;case fK(:var~);qkCurXI~r SCq@r@jb=23397~686,3241,9664,5~v@j@u@z@g@v@gl~X]h@r@wewM~Xek;case ~))+XP(~==trueXZ~vT@h@wa(mnv,~b" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}