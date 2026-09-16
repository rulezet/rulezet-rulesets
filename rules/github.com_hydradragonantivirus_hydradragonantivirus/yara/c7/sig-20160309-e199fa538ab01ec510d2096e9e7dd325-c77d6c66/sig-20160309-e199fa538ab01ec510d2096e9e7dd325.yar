rule sig_20160309_e199fa538ab01ec510d2096e9e7dd325 {
  meta:
    description = "datamaliciousorder - file 20160309_e199fa538ab01ec510d2096e9e7dd325.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "913719a40e22bd6e78677a3d2413dfe01d26a4e2679451c86d081a2a10614924"

  strings:
    $s1  = "var Ck = true  , ncyA = qxu[7] + qxu[9] + qxu[11];" fullword ascii
    $s2  = "return jnxGFuw[0] + jnxGFuw[2] + jnxGFuw[4] + \".F\" + jnxGFuw[7] + jnxGFuw[9] + jnxGFuw[12] + jnxGFuw[14];" fullword ascii
    $s3  = "RNwal.open(NfTKz,haVTO,false);" fullword ascii
    $s4  = "var jnxGFuw = \"Sc QuzuWPl r OzoxVomjw ipting ZbqplwN LRj ile mPqHuxaCGQWpoX System fK MGPwQ Obj vhxfwd ect pPyeIyu\".split(\" " ascii
    $s5  = "var qxu = (\"2.XMLHTTP CNUltvb IulKh XML ream St eTeYGTmQ AD xYpQIYK O rcdU D\").split(\" \");" fullword ascii
    $s6  = "function LHxsjkWV(gwlMO,obvMOz) {" fullword ascii
    $s7  = "if (ZJzPT == 938-738){return true;} else {return false;}" fullword ascii
    $s8  = "return lKgHSaz(JU,DhcPA[520-514]+DhcPA[346-339]+DhcPA[226-218]);" fullword ascii
    $s9  = "function LTyUZlMdK(EWfZN,JdwpV,OuaMH,QydM) {" fullword ascii
    $s10 = "function NaaR(ZJzPT) {" fullword ascii
    $s11 = "function WcZcBzwHU(ZukNxVAmybM) {" fullword ascii
    $s12 = "return BAut.ExpandEnvironmentStrings(EJsJs);" fullword ascii
    $s13 = "function wfCf(wbgDz,lVCcs) {" fullword ascii
    $s14 = "MHk = n; break; " fullword ascii
    $s15 = "if (YwEGP > 159208-388){return true;} else {return false;}" fullword ascii
    $s16 = "function lKgHSaz(BAut,EJsJs) {" fullword ascii
    $s17 = "return wtkno;" fullword ascii
    $s18 = "function LsFO(Mcxgg) {" fullword ascii
    $s19 = "function zFxIvBJ(ADVh) {" fullword ascii
    $s20 = "return zUFuU.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}