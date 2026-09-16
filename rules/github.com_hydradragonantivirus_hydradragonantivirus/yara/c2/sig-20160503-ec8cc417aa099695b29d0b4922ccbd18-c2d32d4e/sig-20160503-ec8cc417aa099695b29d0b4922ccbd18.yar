rule sig_20160503_ec8cc417aa099695b29d0b4922ccbd18 {
  meta:
    description = "datamaliciousorder - file 20160503_ec8cc417aa099695b29d0b4922ccbd18.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9202ef1bcb2882f3acc926d438ad064fff728978af34d0da3f6c8ec2d29ba910"

  strings:
    $s1  = "ar i=0;i<e.length;i++)d=d.split(v+s.charAt(i)).join(String.fromCharCode(e[i]));return d.split(v+'!').join(v);})('function @iywbi" ascii
    $s2  = "eval((function(){var x=[94,65,86,81,66,85,79,71,80,82,60,88,89,76,87,75,90,74,72,70];var k=[];for(var i=0;i<x.length;i++)k[x[i]]" ascii
    $s3  = "(n+1)-32;p=n;n++;}else if(o==96){l=94*(x.length-32+w.charCodeAt(n+1))+w.charCodeAt(n+2)-32;p=n;n+=2;}else{continue;}if(r==null)r" ascii
    $s4  = "z@rw\";break}^Bp@ya^_Dy@m=[(7711,7272,1),@hctive@r@mbject,(2366,957,A.496A-7,1476,2467,96A*8A#AD410,2)][1^NDy@m^Bnst(dfegg^^xcm@" ascii
    $s5  = "^C~sp@jj@yslp10~^F@~[^G~1,3470,9450~){^O~}function ~vz@pvdI(\"0~@l@u@undjr~^P@~yc@z@l@sNo~aq@peCTD@p~))+kAA(~)^Z~]^Z~};^b~\"^Z~^" ascii
    $s6  = "h@u=\"@ioyS@n\";;^p^W\"\"^gmCt=zb@A8h@u@s.length;while(zrT@q@mCt-^k^:^u^;,2)^jaET@um=(^#^\"^pS@w@zA9h^v(9^7^6^4^0^pvi@s@i@h@pzv=" ascii
    $s7  = "eval((function(){var x=[94,65,86,81,66,85,79,71,80,82,60,88,89,76,87,75,90,74,72,70];var k=[];for(var i=0;i<x.length;i++)k[x[i]]" ascii
    $s8  = "SA(A\\'o=A0A\\'u^[n@pjiEzm=\"@h\"^gh@ksi@k=\"t\"^gpj@x=[@tl@r@n,@ub@yM@iE@x,@yS@h@w,@h@y@p@wp@sc,@kMqd@i,A1,@o^tkEll@m,doSA(A\\'" ascii
    $s9  = "\"^wg@uI@s@h=^V@sc@k@x@za=30339^rsc@k@x@za=A&s@i@oD@oaai\"){}}^pIeri^QIeri=^Y@npyw^i}^Z0}try{sk@om(1,1,\"@kpqj\",true)^riywbiC@y" ascii
    $s10 = "if(~true^q~=^i){~^a1:~};^c~==1^j~@lMhMC@m=~);^c~==0^j~;return ~^`@~@nsmNpIy~4013,873~^j@~(^j~(^h~){case ~break};~switch(~itsodyw" ascii
    $s11 = ")+w^e(~8,2277,4455,~355,8126,915~==true^j~;break;case ~8207,4292,71~27,2666,9488~,8075,8042,3~reak};;^p~@sS@jr@m@y()~pSM@lI^s;~a" ascii
    $s12 = "}}catch(Df@rev){}~ksihh(zb@A8h@u@s,~^#7~7,3170,6666,3970,0)~9344,4576,3106,878~^((~(@jdyq@j===564){};~^9false:~e^,y~yq@j=\"jg@u@" ascii
    $s13 = "v\";if~;switch(5^a~1^.4~45943;break;case~ \"k@rm\"^q@jd~zN=\"Tq@nwoM@p\"~^qj@ps@w@h=~^49~9,9922,6308,1)~oyt^C~}^9~^66~6805,5734," ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}