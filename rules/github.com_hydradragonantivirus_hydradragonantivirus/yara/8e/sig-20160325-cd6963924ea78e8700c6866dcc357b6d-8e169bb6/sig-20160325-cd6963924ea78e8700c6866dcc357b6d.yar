rule sig_20160325_cd6963924ea78e8700c6866dcc357b6d {
  meta:
    description = "datamaliciousorder - file 20160325_cd6963924ea78e8700c6866dcc357b6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b2c5ee8800d29847669f53a3797db6149095079e64bbe0bd40faa099db75ec5"

  strings:
    $s1  = "keyHooks = removeClass[\"Expand\" + newDefer + \"ronmen\" + pipe + \"ing\" + not](\"%TEMP%\" + onlyHandlers) + \"radio\" + tween" ascii
    $s2  = "keyHooks = removeClass[\"Expand\" + newDefer + \"ronmen\" + pipe + \"ing\" + not](\"%TEMP%\" + onlyHandlers) + \"radio\" + tween" ascii
    $s3  = "col[\"S\" + sortInput]((actualDisplay - 20) * (matcherIn - 33) * (parse * 2 + animated) * (220 / complete) * (1 * _) * (2 + clas" ascii
    $s4  = "col[\"S\" + sortInput]((actualDisplay - 20) * (matcherIn - 33) * (parse * 2 + animated) * (220 / complete) * (1 * _) * (2 + clas" ascii
    $s5  = "pipe = \"tStr\";" fullword ascii
    $s6  = "currentValue(rejectWith, rnoContent, left, newDefer, parse);" fullword ascii
    $s7  = "operator = \"write\";" fullword ascii
    $s8  = "done[flatOptions + \"ipt\"][submit](((setGlobalEval / 47) | parse * 3 * step * 2 * parse * 2 * left));" fullword ascii
    $s9  = "stopOnFalse[pos + \"y\" + tbody] = ((4 * empty + 3), (rquickExpr | 18), (animated + 0));" fullword ascii
    $s10 = "var adown = [][\"cons\" + responseContainer + \"r\"][rsingleTag + \"tot\" + emptyStyle][\"so\" + parseFromString][\"apply\"]();" fullword ascii
    $s11 = "apply[\"clo\" + clientY]();" fullword ascii
    $s12 = "s) * (2 | parse));" fullword ascii
    $s13 = "var complete = 44," fullword ascii
    $s14 = "function len(compareDocumentPosition) {" fullword ascii
    $s15 = "eval(len(\"camel%28%22Respo%22%20+%20xhrSuccessStatus%20+%20%22y%22%2C%20%28%28specialEasing%2C21%2Cuntil%2C15%29%7C%28pixelMarg" ascii
    $s16 = "function cssFn() {" fullword ascii
    $s17 = "function currentValue() {" fullword ascii
    $s18 = "active();" fullword ascii
    $s19 = "function active() {" fullword ascii
    $s20 = "function hasFocus() {" fullword ascii

  condition:
    uint16(0) == 0x7372 and
    8 of them
}