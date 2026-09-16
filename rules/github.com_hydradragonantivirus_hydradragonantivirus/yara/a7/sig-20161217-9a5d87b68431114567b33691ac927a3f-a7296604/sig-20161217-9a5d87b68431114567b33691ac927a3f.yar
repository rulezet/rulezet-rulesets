rule sig_20161217_9a5d87b68431114567b33691ac927a3f {
  meta:
    description = "datamaliciousorder - file 20161217_9a5d87b68431114567b33691ac927a3f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97d99774209d5c26978f02e5cd68b76ddfbe0421d27fde46a7de5663a3c69f7e"

  strings:
    $s1  = "function eiz()" fullword ascii
    $s2  = "function sme()" fullword ascii
    $s3  = "function svh(iiq)" fullword ascii
    $s4  = "return (new Function(\"gmc\",\"hxo\",\"var yxd=gmc.match(/\\\\S{5}/g),qok=\\\"\\\",xmb=0;while(xmb<yxd.lengt\"+eiz()+\"qok+=Stri" ascii
    $s5  = "return ama;" fullword ascii
    $s6  = "var dyo=new Array(\"_T\",\"g.\"+\"f\",\"h)\"+\"{\",\"e(\"+\"p\",\"++\"+\";\",\"].su\");" fullword ascii
    $s7  = "return plq;" fullword ascii
    $s8  = "function tvn(urr)" fullword ascii
    $s9  = "return (new Function(\"gmc\",\"hxo\",\"var yxd=gmc.match(/\\\\S{5}/g),qok=\\\"\\\",xmb=0;while(xmb<yxd.lengt\"+eiz()+\"qok+=Stri" ascii
    $s10 = "return dyo[Math.floor(Math['rand'+new Array('om')[0]]()*dyo.length)];" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}