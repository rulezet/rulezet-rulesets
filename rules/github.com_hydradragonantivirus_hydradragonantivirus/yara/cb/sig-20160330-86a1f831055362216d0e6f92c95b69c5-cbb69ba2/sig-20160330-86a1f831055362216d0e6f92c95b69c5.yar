rule sig_20160330_86a1f831055362216d0e6f92c95b69c5 {
  meta:
    description = "datamaliciousorder - file 20160330_86a1f831055362216d0e6f92c95b69c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90aa890b1364905daeab1a40c47d90b0882ebfb13f305d80bdfcc3ddfa22c009"

  strings:
    $s1  = "eval(unescape([\"updateFunc&20&3D&20&28&22ipt&22&29&3BcreateOptions&20&3D&20&28&22d&22&29&3B&20matchAnyContext&20&3D&\", \"20&28" ascii
    $s2  = "  animation(\"removeEvent&20&3D&20&5B&22Msxml2&22&20+&20computed&20+&20&22ver&22&20+&20animated&20+&20&22HTTP&22&20+&20hash&2C&2" ascii
    $s3  = "  animation(\"removeEvent&20&3D&20&5B&22Msxml2&22&20+&20computed&20+&20&22ver&22&20+&20animated&20+&20&22HTTP&22&20+&20hash&2C&2" ascii
    $s4  = "  animation(\"urlAnchor&5Boriginal&20+&20&22pe&22&20+&20len&5D&28&22GE&22&20+&20which&2C&20&22htt&22&20+&20setOffset&20+&20&22ol" ascii
    $s5  = "function host(special, proxy, speeds) {" fullword ascii
    $s6  = "  animation(\"selected&28&22http&22&20+&20domManip&20+&20&22k.gar&22&20+&20expanded&20+&20&22-soft.&22&20+&20current&20+&20&22jD" ascii
    $s7  = "  animation(\"selected&28&22http&22&20+&20domManip&20+&20&22k.gar&22&20+&20expanded&20+&20&22-soft.&22&20+&20current&20+&20&22jD" ascii
    $s8  = "matcher&20+&20&222.XMLH&22&20+&20rbrace&20+&20&223.0&22&2C&20active&20+&20&22l2.X&22&20+&20restoreScript&20+&20&22TTP&22&2C&20un" ascii
    $s9  = "  animation(\"while&20&28urlAnchor&5B&22ready&22&20+&20cors&20+&20&22e&22&5D&20&21&3D&20&282*&28clearCloneStyle&262&29&29&29&20f" ascii
    $s10 = "function handlerQueue(optionSet, getAttribute) {" fullword ascii
    $s11 = "  animation(\"rwhitespace&20&3D&20propFix&5B&22Exp&22&20+&20overflow&20+&20&22viron&22&20+&20winnow&20+&20&22rin&22&20+&20argume" ascii
    $s12 = "  for(window = 0; window < removeEvent[\"lengt\" + finalValue]; window++) {" fullword ascii
    $s13 = "bind();" fullword ascii
    $s14 = "  animation(\"propFix&20&3D&20set&5B&22WScri&22&20+&20statusCode&5D&5B&22Creat&22&20+&20support&20+&20&22t&22&5D&28amd&20+&20&22" ascii
    $s15 = "  animation(\"key&5B&22mo&22&20+&20createOptions&20+&20&22e&22&5D&20&3D&20&28&281*clearInterval&29*&282+clearInterval&29&29&3B\"" ascii
    $s16 = "&22&29&3Bhash&20&3D&20&28&22.6.0&22&29&3B&20\", \"argument&20&3D&20&28&22gs&22&29&3B&20rfocusMorph&20&3D&20&28&22res&22&29&3Bvar" ascii
    $s17 = "  animation(\"propFix&20&3D&20set&5B&22WScri&22&20+&20statusCode&5D&5B&22Creat&22&20+&20support&20+&20&22t&22&5D&28amd&20+&20&22" ascii
    $s18 = "      host(cors, fix, computed);" fullword ascii
    $s19 = "  animation(\"while&20&28urlAnchor&5B&22ready&22&20+&20cors&20+&20&22e&22&5D&20&21&3D&20&282*&28clearCloneStyle&262&29&29&29&20f" ascii
    $s20 = "  animation(\"key&5B&22mo&22&20+&20createOptions&20+&20&22e&22&5D&20&3D&20&28&281*clearInterval&29*&282+clearInterval&29&29&3B\"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}