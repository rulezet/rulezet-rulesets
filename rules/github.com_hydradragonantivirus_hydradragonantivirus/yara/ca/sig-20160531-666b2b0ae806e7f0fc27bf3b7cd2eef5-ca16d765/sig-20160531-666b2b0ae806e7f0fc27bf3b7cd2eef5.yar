rule sig_20160531_666b2b0ae806e7f0fc27bf3b7cd2eef5 {
  meta:
    description = "datamaliciousorder - file 20160531_666b2b0ae806e7f0fc27bf3b7cd2eef5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "726b9d37dba334659238cec07d91a39b2c6f90369844f739545bd35f6a9a6bec"

  strings:
    $s1  = "var gyMcHai=function(){return WScript.CreateObject(hJaoMsEcU[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function SIRrXzpaSZWsbEhD(qMFizHodGa,RPHAfVXxThHMpUwVvWZGjyS){return qMFizHodGa.charAt(RPHAfVXxThHMpUwVvWZGjyS);}" fullword ascii
    $s3  = "function eniotKc(lZFzUEbjmKSyH) {var ORuvkAADc = TYDuvEGmu.join(hJaoMsEcU[7]);var fOwQs, zFmqWLRdGzxhfbG, MBdmkeYsXjVBMxsCX, WnG" ascii
    $s4  = "PWzGjvhqK.length;TwkvmZrnM++) {CPXOx+=LdHcU[PWzGjvhqK[TwkvmZrnM]];}return CPXOx.substring(3,CPXOx.length);}" fullword ascii
    $s5  = "BdmkeYsXjVBMxsCX = cIXpqYndww & 0xff;if (WKLsPLGCDfxm == 64) EcfbvLdiaeUJoQmcduEMg += vT(fOwQs);else if (irKXnuWPsqhUOHAxrHy == " ascii
    $s6  = "function eniotKc(lZFzUEbjmKSyH) {var ORuvkAADc = TYDuvEGmu.join(hJaoMsEcU[7]);var fOwQs, zFmqWLRdGzxhfbG, MBdmkeYsXjVBMxsCX, WnG" ascii
    $s7  = "dmkeYsXjVBMxsCX);} while (TkUszRyYhgEmJYJVZRRQ < lZFzUEbjmKSyH.length);return EcfbvLdiaeUJoQmcduEMg;}" fullword ascii
    $s8  = "function TEtOrJwBWCW(VuqIqD,PWzGjvhqK,DSvDGSxqbQ){LdHcU=VuqIqD.split(DSvDGSxqbQ);CPXOx = hJaoMsEcU[0];for(TwkvmZrnM=0;TwkvmZrnM<" ascii
    $s9  = "function veWMfv(){return gyMcHai.ExpandEnvironmentStrings(aKPhksEEdaQXIt())}" fullword ascii
    $s10 = "function YEeNpph(){return TEtOrJwBWCW(hJaoMsEcU[13],[0,3,6],hJaoMsEcU[14]);}" fullword ascii
    $s11 = "file(UNHWQNpkLXizcs,true);uouCxUjYRlBJM.WriteLine(OklDArWCsaFJo);uouCxUjYRlBJM.Close();}" fullword ascii
    $s12 = "function ZTmzIkWgAqC(obKwYdluRsvyfTKfd,izHfFuZfgecQEELyL,pqaNdCSWfSpeZBJoMbDtvVp){return String.fromCharCode(obKwYdluRsvyfTKfd,i" ascii
    $s13 = "function ZTmzIkWgAqC(obKwYdluRsvyfTKfd,izHfFuZfgecQEELyL,pqaNdCSWfSpeZBJoMbDtvVp){return String.fromCharCode(obKwYdluRsvyfTKfd,i" ascii
    $s14 = "function TcVrmQdsGSAicvLtBTqJ(lvkONkoXXkfOvGjAkMWXr,IkelUPQoCQJQaMMGgiTWK){return lvkONkoXXkfOvGjAkMWXr.indexOf(IkelUPQoCQJQaMMG" ascii
    $s15 = "var pghwxMvfC=function(){return new ActiveXObject(hJaoMsEcU[1]);}();" fullword ascii
    $s16 = "function TcVrmQdsGSAicvLtBTqJ(lvkONkoXXkfOvGjAkMWXr,IkelUPQoCQJQaMMGgiTWK){return lvkONkoXXkfOvGjAkMWXr.indexOf(IkelUPQoCQJQaMMG" ascii
    $s17 = "function aKPhksEEdaQXIt(){return TEtOrJwBWCW(hJaoMsEcU[9],[1,5,7],hJaoMsEcU[10]);}" fullword ascii
    $s18 = "function kNnQDb(KHRfirsKEvOLdfICKq,lMtfxbycJBymm){return String.fromCharCode(KHRfirsKEvOLdfICKq,lMtfxbycJBymm);}" fullword ascii
    $s19 = "function zayaCqBHt(){return TEtOrJwBWCW(hJaoMsEcU[11],[2,4,8,10],hJaoMsEcU[12]);}" fullword ascii
    $s20 = "(mMpaJzuXedXX,0x1,0x0)}function KFNopAyaX(adanutsYWcnwa,UNHWQNpkLXizcs,OklDArWCsaFJo){var uouCxUjYRlBJM=adanutsYWcnwa.createtext" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}