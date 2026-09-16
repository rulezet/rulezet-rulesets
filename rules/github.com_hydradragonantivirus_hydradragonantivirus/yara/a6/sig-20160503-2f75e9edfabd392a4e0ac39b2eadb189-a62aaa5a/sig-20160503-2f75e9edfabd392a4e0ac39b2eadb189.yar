rule sig_20160503_2f75e9edfabd392a4e0ac39b2eadb189 {
  meta:
    description = "datamaliciousorder - file 20160503_2f75e9edfabd392a4e0ac39b2eadb189.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e5dca9aa9addf7bcf4dc582c0ffb0a24a3d940eaabdd29545b7ddb5ba57a459"

  strings:
    $s1  = "ar t=0;t<m.length;t++)p=p.split(w+u.charAt(t)).join(String.fromCharCode(m[t]));return p.split(w+'!').join(w);})('function lE@loo" ascii
    $s2  = "eval((function(){var h=[90,81,89,85,65,80,79,75,72,60,82,76,70,87,74,66,88,94,86,71];var e=[];for(var t=0;t<h.length;t++)e[h[t]]" ascii
    $s3  = "function ~[@jbqvv(\"0~))+ttqnw((~=@nI@i(xwn~=@jbqvv(\"0~797,9255,3~=(8291,998~hwu@yoD@r(~ZV@~ZZ5~Z^)~ZaiC@~;return ~()Zd@~(Za@~;" ascii
    $s4  = "eval((function(){var h=[90,81,89,85,65,80,79,75,72,60,82,76,70,87,74,66,88,94,86,71];var e=[];for(var t=0;t<h.length;t++)e[h[t]]" ascii
    $s5  = "(f+1)-32;z=f;f++;}else if(y==96){s=94*(h.length-32+a.charCodeAt(f+1))+a.charCodeAt(f+2)-32;z=f;f+=2;}else{continue;}if(i==null)i" ascii
    $s6  = "s@lZaSEaqzdq=\"@nz@qEm\"ZV1}try{if(lE@loou(true)!=1){t@zws(1,Zi,Zi)}else {if(@m@jb@h(1,0)!=1){t@zws(1,Zi,Zi)}else {var @ys@hMu=(" ascii
    $s7  = "Nw@nih@k\"Zd@g@g@h@mI=@w@rcSye.lengthZdcv@zsif@l@uZPZ!Zdlf@w@u=\"cqg@tpN\";;Zd@ndq=\"\"Zd@loxDT=xwn@u@w.length;while(cv@zsif@l@u" ascii
    $s8  = "0~367,5469,9123,1)~break;case true:~787,1428,3310,2)~497,7ZO7~(3==true){}Zd~@u@w,cv@zsif@l@u~wp@wl@zSZb;~3ZA0~05,6521,6497,7~Z?7" ascii
    $s9  = "eak};~;switch(~2664,383~@wZb~Zgps@~@w@i==11~){case ~;break;~){var ~=Zi~ Dr@uf~;var ~:var ~=true~\"Zl~)Zl~false~ase f~6:var~;if(~" ascii
    $s10 = "e 23Zk~;case 51:if(6==0){~Z1;~bSM@gZb;switch~Z?0:var ~if(wp@wl@zS==0){};~C@sbpv@oZK~Z2:~ZeCuxgn=13840;~z@hwDdZf;break~switch(3Z_" ascii
    $s11 = "okE){[(4049,7339,3112,3853,6049,8384,4899,5830,7924,1),h@iv][(4049,7339,3112,3853,6049,8384,4899,5830,7924,1)]()}}}}catch(pcM@jq" ascii
    $s12 = "7~break}Zdqo~)+@lTdcc@l((~Z`case ~(9575,3563,2~8,8890,825,6~=falseZa~cv@zsif@l@u+~yum@n@r@ic@m~ZI7~703}ZY~ZJ@~1ZUt~tj@t@m@z=72~}" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}