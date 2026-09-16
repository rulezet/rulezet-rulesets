rule Virus_Hijack_Gen_Trojan_ShellObject_fyX_aWevApi_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyX@aWevApi_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6571f831649181b769e7f29e5da1d07bcf0d155c988fff6dfe5659d845226a4"

  strings:
    $s1  = "function getEncryption(password,salt,vcode,isMd5){vcode=vcode||'';password=password||'';var md5Pwd=isMd5?password:md5(password)," ascii
    $s2  = "function getEncryption(password,salt,vcode,isMd5){vcode=vcode||'';password=password||'';var md5Pwd=isMd5?password:md5(password)," ascii
    $s3  = "function getRSAEncryption(password,vcode,isMd5){var str1=isMd5?password:md5(password);var str2=str1+vcode.toUpperCase();var str3" ascii
    $s4  = "function getRSAEncryption(password,vcode,isMd5){var str1=isMd5?password:md5(password);var str2=str1+vcode.toUpperCase();var str3" ascii
    $s5  = "function jm(p,u,c){var pwd=md5(p),h1=hexchar2bin(pwd),salt=uin2hex(u),s2=md5(h1+salt),rsaH1=$.RSA.rsa_encrypt(h1),rsaH1Len=(rsaH" ascii
    $s6  = "function P(t){var z=j();this.abs().divRemTo(t,null,z);if(this.s<0&&z.compareTo(au.ZERO)>0){t.subTo(z,z)}" fullword ascii
    $s7  = "function al(t){var z=j();t.abs().dlShiftTo(this.m.t,z);z.divRemTo(this.m,null,z);if(t.s<0&&z.compareTo(au.ZERO)>0){this.m.subTo(" ascii
    $s8  = "au.prototype.copyTo=aa;au.prototype.fromInt=p;au.prototype.fromString=y;au.prototype.clamp=Q;au.prototype.dlShiftTo=at;au.protot" ascii
    $s9  = "function X(t){if(t.s<0||t.compareTo(this.m)>=0){return t.mod(this.m)}else{return t}}" fullword ascii
    $s10 = "function al(t){var z=j();t.abs().dlShiftTo(this.m.t,z);z.divRemTo(this.m,null,z);if(t.s<0&&z.compareTo(au.ZERO)>0){this.m.subTo(" ascii
    $s11 = "0869A453F27DFDDF83C016D928B3CBF4C7';z='3';var t=new N();t.setPublic(aC,z);return t.encrypt(aD)}" fullword ascii
    $s12 = "s.TEA={encrypt:function(D,C){var B=p(D,C);var A=j(B);return x(A)},enAsBase64:function(F,E){var D=p(F,E);var C=j(D);var A='';for(" ascii
    $s13 = "s.TEA={encrypt:function(D,C){var B=p(D,C);var A=j(B);return x(A)},enAsBase64:function(F,E){var D=p(F,E);var C=j(D);var A='';for(" ascii
    $s14 = "i+2>>2]>>8*((i+2)%4))&255);for(var j=0;j<4;j++){if(i*8+j*6>binarray.length*32){str+=b64pad}else{str+=tab.charAt((triplet>>6*(3-j" ascii
    $s15 = "N.prototype.doPublic=Y;N.prototype.setPublic=q;N.prototype.encrypt=r;var ay;var ak=244837814094590;var ab=((ak&16777215)==157150" ascii
    $s16 = "=$.RSA.rsa_encrypt(str2);return str3}" fullword ascii
    $s17 = "arr=arr.join('');eval('var temp = \\''+arr+'\\'');return temp}" fullword ascii
    $s18 = "function jm(p,u,c){var pwd=md5(p),h1=hexchar2bin(pwd),salt=uin2hex(u),s2=md5(h1+salt),rsaH1=$.RSA.rsa_encrypt(h1),rsaH1Len=(rsaH" ascii
    $s19 = "TEA.initkey(s2);var saltPwd=TEA.enAsBase64(rsaH1Len+rsaH1+TEA.strToBytes(salt)+vcodeLen+hexVcode);TEA.initkey('');__monitor(4883" ascii
    $s20 = "function b64_hmac_md5(key,data){return binl2b64(core_hmac_md5(key,data))}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}