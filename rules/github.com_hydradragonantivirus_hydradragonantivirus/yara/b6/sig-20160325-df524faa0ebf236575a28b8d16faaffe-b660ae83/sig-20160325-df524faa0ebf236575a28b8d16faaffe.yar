rule sig_20160325_df524faa0ebf236575a28b8d16faaffe {
  meta:
    description = "datamaliciousorder - file 20160325_df524faa0ebf236575a28b8d16faaffe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63ec8831af10a946417d56d9d40d2807b216b8610c79e46a98c355ccd7b332af"

  strings:
    $s1  = "keepScripts = \"e\", nodes = \"l2.XM\", compilerCache = \"com/\", cssNormalTransform = \"ucto\", get = \"Envir\", contentType = " ascii
    $s2  = "ajaxSettings = results[\"Expand\" + get + \"onment\" + fadeToggle + \"gs\"](contentType + \"/\") + keepScripts + \"l\" + margin " ascii
    $s3  = "ajaxSettings = results[\"Expand\" + get + \"onment\" + fadeToggle + \"gs\"](contentType + \"/\") + keepScripts + \"l\" + margin " ascii
    $s4  = "getAttribute[\"ty\" + teardown + \"e\"] = ((click - 32) + (textContent, 69, ret));" fullword ascii
    $s5  = "handleObjIn[\"WScr\" + onreadystatechange][\"Slee\" + teardown]((3 * targets * 3 * fns * 3 * targets * (36, finalText, 20) + (sp" ascii
    $s6  = "handleObjIn[\"WScr\" + onreadystatechange][\"Slee\" + teardown]((3 * targets * 3 * fns * 3 * targets * (36, finalText, 20) + (sp" ascii
    $s7  = "getAttribute = new values[scripts + \"eXOb\" + state](\"ADODB\" + disableScript + \"am\");" fullword ascii
    $s8  = "eval(unqueued(\"write%28addToPrefiltersOrTransports%20+%20%22seBo%22%20+%20matcherFromTokens%2C%20%28%28Math.pow%28404%2C%20fns%" ascii
    $s9  = "eval(unqueued(\"write%28addToPrefiltersOrTransports%20+%20%22seBo%22%20+%20matcherFromTokens%2C%20%28%28Math.pow%28404%2C%20fns%" ascii
    $s10 = "returnTrue(cssNormalTransform, keepScripts, binary, teardown);" fullword ascii
    $s11 = "rjsonp = \"R\", createInputPseudo = \"G\", completed = (function timerId.addGetHookIf() {" fullword ascii
    $s12 = "var stopImmediatePropagation = [][\"constr\" + cssNormalTransform + \"r\"][constructor + \"type\"][margin + \"or\" + binary][\"a" ascii
    $s13 = "scripts = \"Activ\", state = \"ject\", fired = 27;" fullword ascii
    $s14 = "success(fired, fired, keepScripts);" fullword ascii
    $s15 = "noGlobal(rclickable, selected, disableScript);" fullword ascii
    $s16 = "eval(unqueued(\"always%20%3D%20getAttribute%3B\"));" fullword ascii
    $s17 = "isSimulated[_ + \"eep\"]((fns * 2 * fns * 3 * soFar & (2707 * fns + 1654)));" fullword ascii
    $s18 = "timeStamp(fns, strAbort, prev, selected, onreadystatechange);" fullword ascii
    $s19 = "binary = \"t\";" fullword ascii
    $s20 = "locked(leadingRelative, margin, margin, completed, state);" fullword ascii

  condition:
    uint16(0) == 0x6f68 and
    8 of them
}