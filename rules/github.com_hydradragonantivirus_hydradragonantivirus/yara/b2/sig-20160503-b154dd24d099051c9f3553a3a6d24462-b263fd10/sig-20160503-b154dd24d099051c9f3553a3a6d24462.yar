rule sig_20160503_b154dd24d099051c9f3553a3a6d24462 {
  meta:
    description = "datamaliciousorder - file 20160503_b154dd24d099051c9f3553a3a6d24462.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e1bc4bf7f3c4c16e30d90e8576642ed9b46e314bc2e0efb425adf621cacbaeb"

  strings:
    $s1  = "eval((function(){var h=[75,85,72,65,71,86,66,76,70,60,82,89,88,90,80,87,94,79,74,81];var g=[];for(var o=0;o<h.length;o++)g[h[o]]" ascii
    $s2  = "ar o=0;o<q.length;o++)j=j.split(s+p.charAt(o)).join(String.fromCharCode(q[o]));return j.split(s+'!').join(s);})('function @iCacM" ascii
    $s3  = "fK/E@r@rb@y=80642K/@qqnh=69928KqqqnhKRKoic@o=K;switch(KvKUKvKh@g@nS=\"ijf@qz@s\";brK!e@vfoDhTKbKMif(3==282)KY@q@ix@x@u@yDDK\"@K?" ascii
    $s4  = "n@r@r=EcS@h@u@zn@r.length;while(KC@pn@r@r-(4639,9653K\\'K:K\\\\SdM@iqK5K Kgmq@z@s=K8K@K]g@q@kN@z@lK\"mq@z@s)K]xE@qgeK\"K8KKK\\'K" ascii
    $s5  = "eval((function(){var h=[75,85,72,65,71,86,66,76,70,60,82,89,88,90,80,87,94,79,74,81];var g=[];for(var o=0;o<h.length;o++)g[h[o]]" ascii
    $s6  = "zuCy@z\";break}KNKmKU0:ifKn==693KVnhv@mu=16261}KBKv:ifKn===\"o@lCNr@ua@y\"){};bK$ou@sD@hE=\"M@v@rIS@q\"KMifKn==197KVxl@xKfKEw@m@" ascii
    $s7  = "b(a@hD,mbxv@yx,cbI@t,C@zu@lNo){switch(0KU\"ENl\":if(C@zu@lNo===1){}K<SnNK_utE@v=86933KMKxn@o@rrStj=\"@r@skMk@yeKin@o@rrStj===511" ascii
    $s8  = "br~))+@ieK[(~KC+(~f(ap@jC@s==591~,9888,7193,2)~true}KM~KB\"~zneEKI~=@s@q@kT@zpM(~hdc@ro@i@rI);~3226,8461,1)~){if(5===tru~;break;" ascii
    $s9  = "ase ~@hdc@ro@i@rI~KE@~}function ~N@gbqS@g@t~t@j@lb@y10~KL@~[KQ~)KS~4639,9653~;return ~;break};~;switch(~(KV~KW@~vt@np(\"0~==Kv){" ascii
    $s10 = "(d+1)-32;a=d;d++;}else if(u==96){r=94*(h.length-32+y.charCodeAt(d+1))+y.charCodeAt(d+2)-32;a=d;d+=2;}else{continue;}if(w==null)w" ascii
    $s11 = "h~reak;case Km:if(~witch(3KU1:var~,6430,3221,3959,475~3,5123,2009,5869,3)~eKN1){case 1:~K.3~KhS@z@r=44305;if~K\\\\Nxovwx=false}~" ascii
    $s12 = "}};@iCacMb(Km,Km,Kv,0)}catch(r@nymf){}~5,8759,5097,4445,0)~eak;case falseKh~=o@rI(EcS@h@u@zn@r,~eK\\\\nrqwo=true};~reak;case tru" ascii
    $s13 = ")+Kp(~rN@hm@hf~){case ~K\\\\@~(K^~Kb;~{}Kg~r@ja@ll~@h@x@o(~){Kx~Kg@~)Kg~\"Kh~@xnw@o~qqn@mq~=Km~=Kv;~@gd@yd~)];var~=Kv}~;Kx~:Kx~" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}