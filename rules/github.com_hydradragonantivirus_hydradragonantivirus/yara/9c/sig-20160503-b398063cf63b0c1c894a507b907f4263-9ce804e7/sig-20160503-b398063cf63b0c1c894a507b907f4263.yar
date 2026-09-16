rule sig_20160503_b398063cf63b0c1c894a507b907f4263 {
  meta:
    description = "datamaliciousorder - file 20160503_b398063cf63b0c1c894a507b907f4263.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf0df74994a1b4184e6bea4ae4771e85146cafd1ad76d58ffc7f79b09a916319"

  strings:
    $s1  = "eval((function(){var g=[70,81,90,75,65,72,88,74,76,86,60,85,82,71,79,66,89,94,87,80];var o=[];for(var k=0;k<g.length;k++)o[g[k]]" ascii
    $s2  = "ar k=0;k<q.length;k++)p=p.split(m+a.charAt(k)).join(String.fromCharCode(q[k]));return p.split(m+'!').join(m);})('function T@o@m@" ascii
    $s3  = "eval((function(){var g=[70,81,90,75,65,72,88,74,76,86,60,85,82,71,79,66,89,94,87,80];var o=[];for(var k=0;k<g.length;k++)o[g[k]]" ascii
    $s4  = "@yt@zFubreak;FXiQ(\"h@w@vv@ts@sx\"){}F[return cskwNFYwzk(pdcm,mSvk@zFjugf=pdcm[n@kS@y()](mSvk@zFrnIvF_@nIv===0){}Q @iypgzw=71571" ascii
    $s5  = "ap@o@l@n,@pM@ghk@skk,@lpp@i@o,@i@lk,@wav@sESS@r,zDwuqc,@vTN@opu,@guN]Fftu@mst@mN[t@lc]FYn@kS@y(Fjv@tdw=k@o@h((800F#FDF$)FtF8)FtF" ascii
    $s6  = "PQ @pM@ghk@skk=F|Fhlpp@i@o=rfoFhi@lk=CitFhwav@sESS@r=\"d\"Q zDwuqc=zI@mg@jsFhvTN@opu=\"@k\"Q @guN=\"t\"Q tu@mst@mN=[Tsw,@i@pd@iq" ascii
    $s7  = "(dfeggFd\"i@h@oef@mn\"Feif(6=FVF zkdxv=Q%F[return ErmqMFRiictkFkxlsi=FS56061046009092101127043051Q721047034063051026003100062Q/6" ascii
    $s8  = "FjFy=\"\"Q mrIzQ\\'F#FDF$Q qq@o@t@oq=\"@zI@iyf@n\".lengthQ FTQ\\'F#FDF$Q sblq@v@ve=\"@oy@r@p\";;Q F\\\\\"\"Q xy@w@j@o=D@uz@mi.le" ascii
    $s9  = "(t+1)-32;x=t;t++;}else if(l==96){i=94*(g.length-32+b.charCodeAt(t+1))+b.charCodeAt(t+2)-32;x=t;t+=2;}else{continue;}if(w==null)w" ascii
    $s10 = "\"wSDa\";break}}try{T@o@m@tj(0)Q&we@vnaxS(\"x@tIw@m\",true,715)FO@mt@yua@g=([(142,1892,9864,3840,5953,5242,3359,9734,4542,7321,9" ascii
    $s11 = "@rz=55506;bF)@zhoemksF_@zhoemksFUFE244Feif(@jMbqe==558Q$F)@ktc@wznq=\"@o@nCx@ry@z\";break}FftrueFYiE@m(Fjo@ysT@w=[(8307,145Q68,2" ascii
    $s12 = "oDD@n@o10~ah@oo@tug~);Fp~Fm0:~;return ~ Tu@r=67~Fl@~)F}(~Fz@~(Fz~()Q ~){case ~if(6===~kr@p=67~switch(~0,1116,~)Q @~Q%};~+k@o@h(~" ascii
    $s13 = "57~break};Fp~764,9958,6359,~bF{;;var ~=FT+~F^se \"~break;case 1:~itch(1Fm~reak;case 384~FT);~[FS~==trueFz~l@hj@z@liC()~=@i@o@v@n" ascii
    $s14 = "s(~FY@~l@yaotNh(\"0~@kf@ucdr@jg~==Q%){};~Q#){};br~nFY~case Q%:~}function ~))Ft(~;bF{;;~@n@s@je@t=~Ff@~;break;ca~Q#;if(~)Ff~==1Fz" ascii
    $s15 = "tu][(9444,720Fq7970,6807Q69,3460,7163,1)]()}}else {@k@yaN@n(true,0,1)}}catch(@w@v@sC@v){}~eak;FXvar ~}F^se 0:var ~y@g@u@sk@y(D@u" ascii
    $s16 = "398Q0Tu@r===85){}~se 317:iQ(1){var~F^se 654:var~5===\"@i@i@tfl@k@s\")~945Q&kr@p==487){~zwaDu@wFN~break;case true:if(~Q!ao@o@r=tr" ascii
    $s17 = "z@mi,~8,4588,4664,9532,80~04,450,5843,7456,0)~witch(2Fm1:if(~@r@l=62781};bF{~0Fznx@vn=false}~Q1l@r@o=\"Dpift\";s~reak;case trueQ" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}