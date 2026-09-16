rule sig_20160503_5e081b7f62ec0f823514e910564794d7 {
  meta:
    description = "datamaliciousorder - file 20160503_5e081b7f62ec0f823514e910564794d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fce179ddebe04d2ffd84989bbbb58b57078b17a07853607285a053fed5eacf2"

  strings:
    $s1  = "ar h=0;h<y.length;h++)b=b.split(q+r.charAt(h)).join(String.fromCharCode(y[h]));return b.split(q+'!').join(q);})('function xtIn(b" ascii
    $s2  = "eval((function(){var t=[82,87,60,81,71,94,88,86,89,75,79,72,70,66,76,85,65,90,74,80];var s=[];for(var h=0;h<t.length;h++)s[t[h]]" ascii
    $s3  = "@yS=56215};R)@v@o@p@u@m@w@n=\"@r@o@rme\";break}RF@zEppl@m(RfTIwDW$b=[(4522,2474,9387,7912,1),@wctive@m@qbject,(2721W-0,9619,1216" ascii
    $s4  = "eval((function(){var t=[82,87,60,81,71,94,88,86,89,75,79,72,70,66,76,85,65,90,74,80];var s=[];for(var h=0;h<t.length;h++)s[t[h]]" ascii
    $s5  = "(o+1)-32;f=o;o++;}else if(x==96){u=94*(t.length-32+a.charCodeAt(o+1))+a.charCodeAt(o+2)-32;f=o;o+=2;}else{continue;}if(n==null)n" ascii
    $s6  = "sR[=\"\"RgoDlg=i@zd.length;while(Rb@i@oDlg-(5132R-R,7,2R/RfW hC@q=(R\"R!Rsa@re@ydxRRRAR+R(R&Rsgw@z@xR*a@re@ydx)Rgn@nnc@hR*Rb+(51" ascii
    $s7  = "R^Ro=\"t\"RgpI@W4u@nz@h=[@tSa@w@q@vMT+r@om@w@t@jq,@jd@x+kwW2N@hbN+@xo@ua@q@w@v@t+@Ro][qb@m]RXpI@W4u@nz@hRNNckMom(@rvW1){switch(2" ascii
    $s8  = "~mri@n@ua@hs~@jd@kc@pafD~}function ~[D@ux@o(\"0~=D@ux@o(\"0~false:Rw~=Rb+~\"RX~Rj;if(~@mnhshu@o(~Rb);~===0Rf~R\\\\@~=Rj){~)R_~cg" ascii
    $s9  = "f@pM\"R3Rks@r@x@u=44355;break}R_1RdRQ@zySjxao=\"Mls@m\"R@fW5R|1===\"d@vuSs\"Rf@xicDg=26470}R8fN@pcg@xx=(197W997,641W987,1366,643" ascii
    $s10 = "3,1681,4694,8693,0)~8251,8895,534W99~@ucMfj=\"M@qolizn\";~eak;case true:Rw~R(,~,4896,6184,9637,1)~R+5~54,5557,2663,3207~break;ca" ascii
    $s11 = "R<c~c@q\";break;case~88:RwCD@p=\"D@~))+RU(~R`;;var ~itch(W;){cas~ox@oRO~70,3530,6436,3~vx@s@or=\"@y@my~0R|5==1){var~e \"@jaxf@r" ascii
    $s12 = " @gw@vRq;~;break;case ~(2220,5768,8~))+Ra(~Rdtrue:~@w@p@ph@zh()~@toW0yCo10~RIj~ q@phe@vS@u=~=dE@k@pmvx(@~RN@~=trueRf~xedi@k@uf()" ascii
    $s13 = "rs~;return ~(Rf@~Re@~;switch(~;break};~kv@vn@s(~s@sd@x@w~(1746,20~){case ~(Rh~){Rw~Rs@~)Rs~=W;;~=fW5~0:Rw~m@rk@m~u@ga@r~b@y@hj~r" ascii
    $s14 = "[(9805,3260,4342,2935,1W\\'398,2W8705W(50,2528,1),@j@jd][(9805,3260,4342,2935,1W\\'398,2W8705W(50,2528,1)]()}}catch(NTTs@q){}~R" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}