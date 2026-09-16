rule sig_20160330_c91f1150b3bfb5d006a5d3ed3cf6ae0e {
  meta:
    description = "datamaliciousorder - file 20160330_c91f1150b3bfb5d006a5d3ed3cf6ae0e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c705898827ea39123e1d180b893f218ba71da11c5565121a2ae834af37034329"

  strings:
    $x1  = "eval(unescape([\"var&20activeElement&20&3D&20&28&22n&22&29&2C&20style&20&3D&20&28&22HTT&22&29&2C&20before&20&3D&20&28\", \"24&29" ascii
    $s2  = "  each(\"fixInput&5B&22op&22&20+&20clientTop&5D&28&22GE&22&20+&20namespaces&2C&20&22htt&22&20+&20get&20+&20&22sserti&22&20+&20pr" ascii
    $s3  = "  each(\"stop&20&3D&20&5BremoveData&20+&20&222.Ser&22&20+&20_default&20+&20&22XMLH&22&20+&20notifyWith&20+&20&22.6.0&22&2C&20rem" ascii
    $s4  = "  each(\"checkDisplay&28attrHooks&20+&20&22p&3A/&22&20+&20curValue&20+&20&22rtioni&22&20+&20restoreScript&20+&20&22om/E&22&20+&2" ascii
    $s5  = "  each(\"seekingTransport&20&3D&20n&5B&22WSc&22&20+&20createHTMLDocument&5D&5B&22Creat&22&20+&20div&20+&20&22t&22&5D&28globalEve" ascii
    $s6  = "  each(\"checkDisplay&28attrHooks&20+&20&22p&3A/&22&20+&20curValue&20+&20&22rtioni&22&20+&20restoreScript&20+&20&22om/E&22&20+&2" ascii
    $s7  = "  each(\"seekingTransport&5B&22Save&22&20+&20unbind&20+&20&22e&22&5D&28mouseenter&2C&20&28&289+before&29&2C&2831*status&29&2C&28" ascii
    $s8  = "  each(\"seekingTransport&5B&22Save&22&20+&20unbind&20+&20&22e&22&5D&28mouseenter&2C&20&28&289+before&29&2C&2831*status&29&2C&28" ascii
    $s9  = "function css(options, responseHeaders, origFn) {" fullword ascii
    $s10 = "attrHandle(speeds, style, host, rprotocol, prependTo);" fullword ascii
    $s11 = "  each(\"fixInput&5B&22op&22&20+&20clientTop&5D&28&22GE&22&20+&20namespaces&2C&20&22htt&22&20+&20get&20+&20&22sserti&22&20+&20pr" ascii
    $s12 = "  for (opener = (0 | srcElements); opener < stop[rbrace + \"gth\"]; opener++) {" fullword ascii
    $s13 = "  each(\"seekingTransport&20&3D&20n&5B&22WSc&22&20+&20createHTMLDocument&5D&5B&22Creat&22&20+&20div&20+&20&22t&22&5D&28globalEve" ascii
    $s14 = "high = cssNormalTransform = n = readyWait = dataFilter.matchedCount();" fullword ascii
    $s15 = "  each(\"while&20&28fixInput&5BprependTo&20+&20&22dySta&22&20+&20rinputs&5D&20&21&3D&20&28Math.pow&28&28pageYOffset-13&29&2C&20&" ascii
    $s16 = "  each(\"stop&20&3D&20&5BremoveData&20+&20&222.Ser&22&20+&20_default&20+&20&22XMLH&22&20+&20notifyWith&20+&20&22.6.0&22&2C&20rem" ascii
    $s17 = "  each(\"seekingTransport&5B&22m&22&20+&20Callbacks&20+&20&22d&22&20+&20checkOn&5D&20&3D&20&28&283*dirruns&29/&284*isXML+2&29&29" ascii
    $s18 = "  each(\"seekingTransport&5B&22m&22&20+&20Callbacks&20+&20&22d&22&20+&20checkOn&5D&20&3D&20&28&283*dirruns&29/&284*isXML+2&29&29" ascii
    $s19 = "function detectDuplicates(contentDocument, rmouseEvent) {" fullword ascii
    $s20 = "function checkDisplay() {" fullword ascii

  condition:
    uint16(0) == 0x6674 and
    1 of ($x*) and 4 of them
}