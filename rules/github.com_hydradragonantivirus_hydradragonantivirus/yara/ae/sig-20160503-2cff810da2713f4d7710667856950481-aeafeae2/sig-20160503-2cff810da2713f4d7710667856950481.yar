rule sig_20160503_2cff810da2713f4d7710667856950481 {
  meta:
    description = "datamaliciousorder - file 20160503_2cff810da2713f4d7710667856950481.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "544816c6378a5ea3a32e787ba6b76e03e19297113a21501f5d6e979b1e43219c"

  strings:
    $s1  = "eval((function(){var s=[85,80,88,86,89,66,70,81,74,75,72,60,76,94,71,79,82,90,87,65];var a=[];for(var j=0;j<s.length;j++)a[s[j]]" ascii
    $s2  = "nvw@z(0)==1){if(unz@jy(P%,true,P%,\"v@z@j\")==1UkCyxcu=([(2831,7404,7585,0),@yScript])[(28P\"87,191U}1,6213,99,1385,34P 30,2391," ascii
    $s3  = "ar j=0;j<o.length;j++)z=z.split(x+p.charAt(j)).join(String.fromCharCode(o[j]));return z.split(x+'!').join(x);})('function unz@jy" ascii
    $s4  = "wk@j)U]5U:@yg@kTk@v=69397UB425P#x@u@niIeN=\"eoEN\"UB\"dix@w@pp@sUnn@n@p=17224;brUC3)Ut219:U{qh@o@yMUmU$Tc@m@w@s=59823P-Tc@m@w@s=" ascii
    $s5  = "eval((function(){var s=[85,80,88,86,89,66,70,81,74,75,72,60,76,94,71,79,82,90,87,65];var a=[];for(var j=0;j<s.length;j++)a[s[j]]" ascii
    $s6  = "(q+1)-32;g=q;q++;}else if(m==96){t=94*(s.length-32+f.charCodeAt(q+1))+f.charCodeAt(q+2)-32;g=q;q+=2;}else{continue;}if(r==null)r" ascii
    $s7  = "ngth;while(edhySx@roIaTS-U=Ukjd@v=U3U!UxNs@pm=UcU9U5Ulo@jk@s=@U Ns@pmUoo@vCN@q=@U UcU=)Ulhf@veDdND=@U eUjP,@hf@veDdND+@o@jk@s+o@" ascii
    $s8  = "=@mrUv+j@xh@waq[nSy@g@n](UhUob@wSDNck=(9115,9165,5568,4P)UsUUUNUD);edhySx=Ucb@wSDNck}UVmrUvUQyttg@v@j(){switch(0)Ut514P#i@gStbkU" ascii
    $s9  = "ction ~))+Uq(~Ud;;;~9,8Us8~81,676,754~U\\\\@~r @nqnc=\"~}U]~Uz;if(~=Um){~m@vSf@k()~;return ~;switch(~ ra@mT@h~Uk@~(Uo~(Uk~Ut\"~e" ascii
    $s10 = ",191U}1,6213,99,1385,34P 30,2391,1),woc@ht][(28P\"87,191U}1,6213,99,1385,34P 30,2391,1)]()}}}else {P.wCN=\"CI@zxl@m\"}}catch(C@w" ascii
    $s11 = "x+~;break}~@hmscE(~;;Ux~;break;~Ejhql@u~k@wd@uE~dhySx);~){P.~Ux@~=P%~\"P#~)Ux~;r@hSl~s@szS(~P)7~797,53~{case ~)];var~n@x@zt~true" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}