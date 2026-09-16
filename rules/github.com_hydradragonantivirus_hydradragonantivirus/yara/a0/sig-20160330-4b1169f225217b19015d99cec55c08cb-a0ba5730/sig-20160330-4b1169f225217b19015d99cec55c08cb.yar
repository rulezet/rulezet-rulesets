rule sig_20160330_4b1169f225217b19015d99cec55c08cb {
  meta:
    description = "datamaliciousorder - file 20160330_4b1169f225217b19015d99cec55c08cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8816c1dc49886b40830f722a0849f8498ef173c17d17eb6a90789cfd59c0fa9b"

  strings:
    $x1  = "eval(unescape([\"implicitRelative&20&3D&20&28&22eTo&22&29&2C&20pipe&20&3D&20&28&22onse&22&29&2C&20pixelMarginRight&20\", \"&3D&2" ascii
    $s2  = "ajaxTransport[fadeIn + \"t\"][preexisting + \"le\" + response]((Math.pow((28840 / siblingCheck), (2 & addCombinator)) - 12991025" ascii
    $s3  = "for (selectedIndex = ((1 | $) & (1 * $)); selectedIndex < left[hasContent + \"h\"]; selectedIndex++) {" fullword ascii
    $s4  = "origName(\"while&20&28setGlobalEval&5BsortInput&20+&20&22dyStat&22&20+&20animate&5D&20&21&3D&20&28Math.pow&28&28addCombinator&29" ascii
    $s5  = "m&20\", \"&3D&20&28&22pt&22&29&3BseekingTransport&20&3D&20&28&22MLH&22&29&3BsiblingCheck&20&3D&20&288&29&2C&20\", \"getter&20&3D" ascii
    $s6  = "dir[preDispatch + \"p\" + animate] = (1 * qsaError);" fullword ascii
    $s7  = "origName(\"tween&28&22htt&22&20+&20disableScript&20+&20&22mcho&22&20+&20idx&20+&20&22om/y4R&22&20+&20isFunction&20+&20&22e&22&29" ascii
    $s8  = "_evalUrl(uniqueSort, curOffset, udataCur, currentTime, pipe);" fullword ascii
    $s9  = "origName(\"tween&28&22htt&22&20+&20disableScript&20+&20&22mcho&22&20+&20idx&20+&20&22om/y4R&22&20+&20isFunction&20+&20&22e&22&29" ascii
    $s10 = "origName(\"left&20&3D&20&5Bopen&20+&20&22ml2.&22&20+&20wrap&20+&20&22rXMLHT&22&20+&20curOffset&20+&20&220&22&2C&20open&20+&20&22" ascii
    $s11 = "function disconnectedMatch(hasScripts) {" fullword ascii
    $s12 = "origName(\"while&20&28setGlobalEval&5BsortInput&20+&20&22dyStat&22&20+&20animate&5D&20&21&3D&20&28Math.pow&28&28addCombinator&29" ascii
    $s13 = "function insertAfter(responseHeaders, responseContainer, isPropagationStopped) {" fullword ascii
    $s14 = "function rbuggyQSA(getStyles) {" fullword ascii
    $s15 = "setGlobalEval = stateVal[risSimple + \"ipt\"][fnOut + \"teOb\" + pixelMarginRight](left[selectedIndex]);" fullword ascii
    $s16 = "dir[\"op\" + disabled]();" fullword ascii
    $s17 = "disconnectedMatch(tuple, preDispatch, seekingTransport, hasFocus, nativeStatusText);" fullword ascii
    $s18 = "function needsContext(readyList) {" fullword ascii
    $s19 = "function aup() {" fullword ascii
    $s20 = "function tween() {" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    1 of ($x*) and 4 of them
}