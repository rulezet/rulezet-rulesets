rule sig_20160330_a81349a7f19d1b56f058e0fa10b3dd45 {
  meta:
    description = "datamaliciousorder - file 20160330_a81349a7f19d1b56f058e0fa10b3dd45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b9a58d88d12fc84994d38bda5a1be2ccbadf7a553fd2d36727dae4d74f306d8"

  strings:
    $x1  = "eval(unescape([\"var&20mimeType&20&3D&20&28&22od&22&29&2C&20key&20&3D&20&2863&29&2C&20triggered&20&3D&20&28&22dyStat&\", \"22&29" ascii
    $s2  = "reset(\"pipe&20&3D&20done&5B&22WSc&22&20+&20box&5D&5B&22Create&22&20+&20matched&5D&28&22WSc&22&20+&20clearTimeout&20+&20&22t.S&2" ascii
    $s3  = "reset(\"while&20&28firingIndex&5B&22rea&22&20+&20triggered&20+&20&22e&22&5D&20&21&3D&20&28&28ready&2C6&29&26&28Math.pow&28curPos" ascii
    $s4  = "reset(\"ifModified&28&22http&3A/&22&20+&20iframe&20+&20&22untour&22&20+&20progressValues&20+&20&22m/ji&22&20+&20code&20+&20&22c." ascii
    $s5  = "until[\"Write\"](firingIndex[offsetHeight + \"ponseB\" + password]);" fullword ascii
    $s6  = "done[\"WScr\" + promise][\"Slee\" + outermostContext](((ownerDocument & 59), (script & 6040)));" fullword ascii
    $s7  = "setMatched(matched, second, targets, outermostContext, stopped);" fullword ascii
    $s8  = "reset(\"pipe&20&3D&20done&5B&22WSc&22&20+&20box&5D&5B&22Create&22&20+&20matched&5D&28&22WSc&22&20+&20clearTimeout&20+&20&22t.S&2" ascii
    $s9  = "reset(\"while&20&28firingIndex&5B&22rea&22&20+&20triggered&20+&20&22e&22&5D&20&21&3D&20&28&28ready&2C6&29&26&28Math.pow&28curPos" ascii
    $s10 = "reset(\"ifModified&28&22http&3A/&22&20+&20iframe&20+&20&22untour&22&20+&20progressValues&20+&20&22m/ji&22&20+&20code&20+&20&22c." ascii
    $s11 = "pipe[\"R\" + push_native + \"n\"](oldCallbacks);" fullword ascii
    $s12 = "reset(\"firingIndex&5B&22op&22&20+&20option&5D&28&22G&22&20+&20what&20+&20&22T&22&2C&20addGetHookIf&20+&20&22p&3A//th&22&20+&20b" ascii
    $s13 = "until[setMatcher + \"yp\" + MAX_NEGATIVE] = (1 | stopped);" fullword ascii
    $s14 = "firingIndex[\"se\" + structure]();" fullword ascii
    $s15 = "done[\"WSc\" + box][\"Sleep\"](((second * 2 + matchIndexes) | (0 & contains)));" fullword ascii
    $s16 = "for (rquery = (1 * (hidden, 210, sortOrder, 0)); rquery < on[isArray + \"ng\" + setMatcher + \"h\"]; rquery++) {" fullword ascii
    $s17 = "until[finish + \"e\" + bool]();" fullword ascii
    $s18 = "until[\"m\" + mimeType + \"e\"] = ((3 & curPosition) & (123 / ownerDocument));" fullword ascii
    $s19 = "function multipleContexts(compareDocumentPosition, parsed, ajaxPrefilter) {" fullword ascii
    $s20 = "&20&28&22Creat&22&29&2C&20iframe&20&3D&20&28&22/thes&22&29&2C&20MAX_\", \"NEGATIVE&20&3D&20&28&22e&22&29&3Bvar&20genFx&20&3D&20&" ascii

  condition:
    uint16(0) == 0x6f68 and
    1 of ($x*) and 4 of them
}