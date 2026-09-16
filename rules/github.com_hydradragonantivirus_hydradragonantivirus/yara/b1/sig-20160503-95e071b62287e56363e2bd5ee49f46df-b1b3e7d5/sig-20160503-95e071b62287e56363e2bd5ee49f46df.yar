rule sig_20160503_95e071b62287e56363e2bd5ee49f46df {
  meta:
    description = "datamaliciousorder - file 20160503_95e071b62287e56363e2bd5ee49f46df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4d89f65435754b18355bdf69b7ce9965a21ebb1dc5fca9672bfef4da9b2c8c1"

  strings:
    $s1  = "ar a=0;a<j.length;a++)f=f.split(p+t.charAt(a)).join(String.fromCharCode(j[a]));return f.split(p+'!').join(p);})('function @zgG6d" ascii
    $s2  = "eval((function(){var m=[65,71,76,79,90,85,60,89,82,87,75,70,86,66,80,72,94,81,88,74];var q=[];for(var a=0;a<m.length;a++)q[m[a]]" ascii
    $s3  = ",@y@oj@v+C@xk@o@lr@h@l+xey@ocb+Ah][ctMisvm]AKuq@pNhgvAFkx@zlr(sdTdG%itch(3Ag654:if(6==330Aiy@z@rn@u=\"q@h@rCl\"}A4G I@jqEg=24743" ascii
    $s4  = "eval((function(){var m=[65,71,76,79,90,85,60,89,82,87,75,70,86,66,80,72,94,81,88,74];var q=[];for(var a=0;a<m.length;a++)q[m[a]]" ascii
    $s5  = "36;Aw}AqDuT=21243AqgyahG4Dtnu@naAsgyah@v=AkAf Aa\"\"Ajt@jo=Se@z.length;while(@GA@m@t@jo-A=A/AilI@gSrxyA6AjvEDpbAeAnA,A+A\\'Ajr@u" ascii
    $s6  = "(l+1)-32;v=l;l++;}else if(s==96){w=94*(m.length-32+n.charCodeAt(l+1))+n.charCodeAt(l+2)-32;v=l;l+=2;}else{continue;}if(b==null)b" ascii
    $s7  = "@orbTm@q@y](G*AbznheN@iy@h=(970,563A@A731A8);@GAAe@znheN@iy@h}A]woAZAHeG2(Eckn@z,l@hh@iG%itch(l@hh@iAg\"spSAlr@g@h@x=37673G/r@g@" ascii
    $s8  = "rS\"AqSzi@lAIc@v@xA|i==0){}}try{eG2(G1,343);ucDvnE(46,25,\"wTI@qTvhy\");@zgG6d(\"@u@i@p@lf@uuo\",377AbsSz@r@i@sMj=([(2253,2937,3" ascii
    $s9  = "'1),S@sa][(6881,8G(194,65,3655,12G)86,1G\\'1)]()}}catch(x@gh@x){}~itch(7A[var ~246:if(3=Ak){va~=A)2~@p@tyi@n@l@g=78125;~\"oSqgN" ascii
    $s10 = "M~))+AU(~(4456,9300,35~};break}Aq~@y@u@lzMf@n()~5,3858,7655,6~AD\"~==falseAi~wCxb@u@i@s()~;Aw;case ~==trueAi~AH@~r Ec@i@oxs=~}fu" ascii
    $s11 = "A_~=kfyvE@p(~q@x@rT@yj~Ag1:~zDo(Se@z,~;return ~Ad@~;switch(~(970,563~ksazI@o=~)Aj~()Aq~(Ai~=@GA+~){};var~){case ~@rkCpuE~){G ~Aq" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}