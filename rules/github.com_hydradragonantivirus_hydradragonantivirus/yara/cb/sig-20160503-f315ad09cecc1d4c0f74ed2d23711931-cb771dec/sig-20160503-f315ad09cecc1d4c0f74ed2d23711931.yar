rule sig_20160503_f315ad09cecc1d4c0f74ed2d23711931 {
  meta:
    description = "datamaliciousorder - file 20160503_f315ad09cecc1d4c0f74ed2d23711931.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83fdce58da3eecf08fa4976adbea9d3944ac6edb8a645015f7698024848c68fc"

  strings:
    $s1  = "z@xd@i(true)RiuaIx@vb=([(6385,3609,4354,1902,259,8283,2037,6833,0),@hScript])[(8176,7198,8927,7498,2648,1)]RahC@ougM=uaIx@vbRO41" ascii
    $s2  = "eval((function(){var q=[82,87,90,81,75,66,76,71,79,60,72,88,94,65,89,70,85,86,80,74];var u=[];for(var t=0;t<q.length;t++)u[q[t]]" ascii
    $s3  = "ar t=0;t<c.length;t++)y=y.split(g+i.charAt(t)).join(String.fromCharCode(c[t]));return y.split(g+'!').join(g);})('function @objc@" ascii
    $s4  = "80:var ~witch(trueR]\"~1818,9979,3720,724~\"x@R-~ep@vg@u@umRfb~e@oRb;break};~R- ~ @wC@rs@kz=29407~ @l@im=45413;va~ziCbq=\"xb@kb" ascii
    $s5  = "88:RqcjIjRfbR CcTe@z=55488R8RJwtvDRb;if(wtvD===1R`k@j@rSa@j=\"bEozgq\"};break}Ritq@zM=\"chql@mq@i\";;RiM@yhr@v@htg= new @nj@jlwf" ascii
    $s6  = "c@wng=RT32034017\"Rk6==R;f@wrmIeTRYR=RO08023032047Rrp@qaIc@wng,@uCq,false);R?RB3;R=RO20Rn3037\")]Rc D@k@q@q@y@njg=RT520040550400" ascii
    $s7  = "5485,2402,2549,1309,0))};T@k@r@rj(RZ,deqEId)RImy@xMy(bknd@kgR`iqERbRic@vtiq@ti=41236}try{@objc@w@m(\"n@g@xDb\",1);my@xMy(true);x" ascii
    $s8  = "eval((function(){var q=[82,87,90,81,75,66,76,71,79,60,72,88,94,65,89,70,85,86,80,74];var u=[];for(var t=0;t<q.length;t++)u[q[t]]" ascii
    $s9  = "@w=\"@kz@wm@vvC\"};break}REjrjNnaC(fErR`u@h@ts=parseInt(fErRPu@h@tsRIrSfdRSr@jlS@j=\"fRLr@jlS@jREx@om@yaSR\\\\ul@yq@z=\"r\"RRul@" ascii
    $s10 = "p@zN=8726RipgDw@z=7314RIxey@qyqRSm@m@z=[(7437,100,3311,3118,5303,1979,7745,3553,7017,2518,1),@tctive@r@object,(2570,6292,5666,92" ascii
    $s11 = "(w+1)-32;v=w;w++;}else if(d==96){h=94*(q.length-32+a.charCodeAt(w+1))+a.charCodeAt(w+2)-32;v=w;w+=2;}else{continue;}if(x==null)x" ascii
    $s12 = "=\"wy@gwRln@qT@n@kDx===0){}RiR_=\"\"RaqNp@ykhc=@m@uji.length;while(RM@p@qNp@ykhc-(331R<R7R>R`kp@m@l@x=RdR%R\"Riq@o@idz=R99723R5R" ascii
    $s13 = "3000,3)~RI@~@x@om@yaS()~)RN~6291,5680,3~}function ~false:Rq~;break};;;~\"RR@~N@m@ky@w@o~)+@knTMt((~[RT~)RR~)RX~;return ~R\\\\@~@" ascii
    $s14 = "k(\"0~()Ra~;switch(~jeb@qsDp~)+l@uD((~Rb};~@g@gf@ot~=@r@lir(~(R`~){case ~=Rd~CgeSc@m~){Rq~Ri@~=false~();var~(9233,~1:Rq~Rj;~C@oN" ascii
    $s15 = "@i@xxf=78438;if(@w@nS@i@xxf=Rb){}R8Rejt@z=\"nMzqCRljt@z==262R`mb@qlnd=52086}R8\"u@wz\":Rqheg@igp=\"@jE@nCe\";break}Raqs@o@m@rRbR" ascii
    $s16 = "76,7198,8927,7498,2648,1),wzStb][(8176,7198,8927,7498,2648,1)]()}}catch(lyCtS@r@o){}~reak;case true:Rq~R%2~2,8053,9896,9469,0)~R" ascii
    $s17 = "reak;case ~RM+(~@q@r@vbzix@g~=falseR`~6,5560,453,5~@q@m@v@rCwkf~7421,4477,2)~Rq@nsx@yMr~73,3532,3733~RH7~z=\"j@rno@j\";~RM);~,26" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}