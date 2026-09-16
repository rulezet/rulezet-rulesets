rule sig_20160503_38de1a058ce130a0d638440027c5e95e {
  meta:
    description = "datamaliciousorder - file 20160503_38de1a058ce130a0d638440027c5e95e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4735b1b8133ce2443f6f9198dcbd6c34b8270e186e1e5de684be07d0dd1c2b7"

  strings:
    $s1  = "eval((function(){var v=[74,65,66,86,75,70,76,79,60,94,85,81,87,72,90,71,80,89,82,88];var n=[];for(var z=0;z<v.length;z++)n[v[z]]" ascii
    $s2  = "w\")!=1){@sNsuCw(0,399,680,Jh)}else {JvN@roC=([(4256,7791,0),@sScript])[(9074,74Jy630,8870,Jz3205,1JZirE=N@roCJ:29051A 39\"JZotT" ascii
    $s3  = "ar z=0;z<w.length;z++)a=a.split(l+t.charAt(z)).join(String.fromCharCode(w[z]));return a.split(l+'!').join(l);})('function @un@lo" ascii
    $s4  = "(i+1)-32;k=i;i++;}else if(f==96){m=94*(v.length-32+p.charCodeAt(i+1))+p.charCodeAt(i+2)-32;k=i;i+=2;}else{continue;}if(u==null)u" ascii
    $s5  = "@lw=[uaxiyj@s+Cc@rgJxr,o@ha+@ip@yq@x@qx+q@y@w@kSmSr+JR][Iz@if@wea]JEv@lwJ>m@wx(SSp@l@kwp){switch(7JUJhJs2J^J[j@zp=\"@iwto@h\"JVJ" ascii
    $s6  = "6===1J3647Jew@hDS=\"stCC\"J81Je@q@lmx=68725J4jSI=\"\"Jdxg@q@yj=aJxC@vj@rt.length;while(JC@oxg@q@yj-JWJ-JSny@JoyJ.J#J\"JduzIEJ;J," ascii
    $s7  = "eval((function(){var v=[74,65,66,86,75,70,76,79,60,94,85,81,87,72,90,71,80,89,82,88];var n=[];for(var z=0;z<v.length;z++)n[v[z]]" ascii
    $s8  = "@~tTI@q@q()~\"JL~j@l@t@rh(~)JY(~)+@h@w@t(~w@nei@u10~;return ~){}Jd~(JS~;switch(~JT@~Jc};~@wi@xS@x~J[@~()Jd~){case ~}Jc~(6692,7~=" ascii
    $s9  = "58,4Jz4276,244~J\\'c~c@zt@i==\"aq@i\"){};~eak;case trueJe~zt@i=42920Jus@y~J,3~3183,6051,6475,1)~;d@qDJ:~;case falseJe~(2430,1152" ascii
    $s10 = "JdC@k@tMI~Jc;case ~=@jeyD@jr(\"0~[@jeyD@jr(\"0~=JC+~(40,2616,264~JC);~JB@~)JJ(~J[s@yc@~@jejdw@m@me~}function ~aNfp@x@w@t~J];if(~" ascii
    $s11 = "1),@vC@jmj@mu][(9074,74Jy630,8870,Jz3205,1)]()}};@s@lpqr(0,1,1)}catch(rf@qI@rk@i){}~@n@zo(aJxC@vj@rt,~J#0~0,2558,2387,5834,0)~33" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}