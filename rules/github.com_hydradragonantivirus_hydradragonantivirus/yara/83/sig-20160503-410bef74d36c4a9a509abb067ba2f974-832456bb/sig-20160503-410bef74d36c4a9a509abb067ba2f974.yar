rule sig_20160503_410bef74d36c4a9a509abb067ba2f974 {
  meta:
    description = "datamaliciousorder - file 20160503_410bef74d36c4a9a509abb067ba2f974.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd210590ff4ec82be3eb020fe34e26f646ca0f1620c2e0cf80e90d8f0559d005"

  strings:
    $s1  = "ar h=0;h<d.length;h++)c=c.split(y+z.charAt(h)).join(String.fromCharCode(d[h]));return c.split(y+'!').join(y);})('function @uC@zv" ascii
    $s2  = "eval((function(){var g=[80,85,86,65,75,72,87,79,66,90,71,70,60,76,82,89,81,94,74,88];var v=[];for(var h=0;h<g.length;h++)v[g[h]]" ascii
    $s3  = "=\"@m@m@u@n@lr\";~P60:var ~(330P`9069,1))~ kvv@oM@vP[};~oxDTpIMPA~){}P6~;break}PL~=P:+(~=PUb(cs@t,~PX;;;var ~P6\"~PV){var ~=(305" ascii
    $s4  = "537,2936,2044,9059,9033,1720,7873,4170,7260,2703,200)){switch(4)P;c@pq@py=82825Pic@pq@py=P9I@r@okfw@k=66714}P6677Pj5=P4ckmEnmP^P" ascii
    $s5  = "eval((function(){var g=[80,85,86,65,75,72,87,79,66,90,71,70,60,76,82,89,81,94,74,88];var v=[];for(var h=0;h<g.length;h++)v[g[h]]" ascii
    $s6  = "(m+1)-32;i=m;m++;}else if(o==96){u=94*(g.length-32+s.charCodeAt(m+1))+s.charCodeAt(m+2)-32;i=m;m+=2;}else{continue;}if(r==null)r" ascii
    $s7  = "i@vx=\"\"PaPuP5PZyM@i@zTmi@t=\"Dj@lcSv@zMyyp\".lengthPaP:P5PaC@u@h@u@q=\"oazTt@g\";;PaPy=\"\"PZuaTax=cs@t.length;while(P:@s@uaTa" ascii
    $s8  = "i@vx+@je@lxnui@h[@z@m@heu](Pu)PaEvwrb=P<;P:=P:+Evwrb}PCi@vxP@Ex@ujT@g(bs@j@n,qbok){switch(736){P?qukCy@wj=\"frN@i\"PiqukCy@wjP4z" ascii
    $s9  = "[~)]Pa~;break}~){var ~Pa@~=false~\"Pb~,4382,~Pc}~false:~,3623,~;var ~:var ~=Pm~)Pi~69,66~Pi@~@h@o@~7,897~;if(~:if(~0210~0060~tru" ascii
    $s10 = "kN(pnoDE@n){switch(\"ei@znD\"PSP_var @rvhrb=42175;bP\\'v@hSoyg@g=14088;bP\\'@g@rcf@zPE@g@rcf@z==Pc){}P> C@p@pP[PiC@p@p===\"I@kqo" ascii
    $s11 = "brP @j@rxlr@r=\"@vsul@w\";brP maTe@rkb=\"@z@u@vz@t@hg\"PX;;PJus@r@pgdpP@bzT@qb(@m@whiIp,grf@r@z@vPRgpo@l@kv=@m@whiIp[@w@hC@ksqj(" ascii
    $s12 = "@m@olbPRzvoy@ul@h@y=[@vgvlc(),PG,PB,\"m\",@yeSt(),\"h\",vD@g(),PG,@yeSt(),PB,\"d\",Nzc@qTx@n()]PCzvoy@ul@h@y[@hfMt@m@olb]P@T@wCd" ascii
    $s13 = "151,4083,5Pd@k@jfh){[(228Ph7,1962,7Pt6943P]1),tIPgp@k][(228Ph7,1962,7Pt6943P]1)]()}}}}catch(@kf@rr){}~eak;case P_var ~(@g@km=PV)" ascii
    $s14 = "w@k@h(\"0~Pc;if(~)PL~jSCr@tD()~\"PJ~+@oThr@u(~;return ~(PR~;switch(~NsD@yjy(~lz@ubI10~PTl~=oNwqhi(~()Pa~PY@~){case ~)PZ~q@g@w@l~" ascii
    $s15 = "77,0)~;break;case ~))+PM(~))PI(~==truePY~Nh@yyI@k@g@v~{case 1Pb~(5504,739,3)~P@@~PX;var~case 0Pb~}function ~[PD~e@y@imSc()~PJ@~q" ascii
    $s16 = "{var~zgo@j@pEjPA~8,561,5551,7815,497~7131,5233,8315,1648~b(cs@t,P:~7,9703,5586,9008,2)~reak;case truePb~{var @g@km=76922;if~v@ph" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}