rule sig_20160503_a6b4ff40ecf7f2ac925fd1fc0bee3151 {
  meta:
    description = "datamaliciousorder - file 20160503_a6b4ff40ecf7f2ac925fd1fc0bee3151.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d0eb9b7cf4f94eb24914d504c5bd8c6d0d41eb0970b573857fcaa98dc5301b4"

  strings:
    $s1  = "ar h=0;h<t.length;h++)i=i.split(e+l.charAt(h)).join(String.fromCharCode(t[h]));return i.split(e+'!').join(e);})('function @w@pgz" ascii
    $s2  = "eval((function(){var k=[90,89,65,87,75,72,71,60,81,88,82,74,94,79,70,80,66,85,86,76];var q=[];for(var h=0;h<k.length;h++)q[k[h]]" ascii
    $s3  = "eval((function(){var k=[90,89,65,87,75,72,71,60,81,88,82,74,94,79,70,80,66,85,86,76];var q=[];for(var h=0;h<k.length;h++)q[k[h]]" ascii
    $s4  = ")~5856,6691,6292,224~=ceT@pE@q@w(@iz@r,~Z\\'x~x@lt@q=\"miqfd@v\"};~Z:true:~if(2==602Zbip~Z.,~,964,4484,7602,1)~dgwc@r@g@kZ[~(914" ascii
    $s5  = "(f+1)-32;m=f;f++;}else if(c==96){v=94*(k.length-32+o.charCodeAt(f+1))+o.charCodeAt(f+2)-32;m=f;f+=2;}else{continue;}if(s==null)s" ascii
    $s6  = "ZL);~c@j@r@phlut~}function ~Zc;if(~=Zc){}~\"ZI~;Zh;;;~lfDa@m@v10~Zayh@z~ZM@~)ZU~24,9480,3~D@mh@tCCC~;return ~;swiY!~(ZW~ZY\"~)Z^" ascii
    $s7  = "engthZiZL=Z+Z\"Z!ZisfvC=\"@t@grqpq\"Z\\\\ZR=\"\"ZizCn=@iz@r.length;while(ZL@nzCn-(4Z0ZbCx@j=Z+Z\"Z!Ziw@ue@hZ<8Z-ZKZ.Z)ZiDD@zZ#w@" ascii
    $s8  = "zISy@i@r@p=33404;bZ/s@l@v=78646;Zh}try{@w@pgzyf(true,true);onES(1);zaxgl(791,265,0ZaCkwu=([(7453,3538,3882,9297,9127,5810,4726,0" ascii
    $s9  = "985,2118,~reak;case Zm:~902,6656,8882,76~573,572,121,6762~reak;case 0Zj~536,9756,2431,2)~Z49~916,5052,8808,3)~vbI=\"@y@l@lpjd\";" ascii
    $s10 = "yt@z@zn~e;Zh~ZV@~)+@vIx((~(Za~Zb@~(Zb~){case ~=nTo(\"0~[nTo(\"0~;;Zi~jksh@jy~)+ulx((~=lIoen(~=Zk)~)Zi~){Zq~=Zm~giwxDq~m@o@pc~)];" ascii
    $s11 = "73,7934,5423,1~9264,7018,3821,~=41415Ziorb@~d@q@o@xlZ[~}Z:~@j@u@j@uk@rim~;break;case ~ifN@pw@r@h()~=ZL+(~ZB@~=Z`{};~1248,9132,9~" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}