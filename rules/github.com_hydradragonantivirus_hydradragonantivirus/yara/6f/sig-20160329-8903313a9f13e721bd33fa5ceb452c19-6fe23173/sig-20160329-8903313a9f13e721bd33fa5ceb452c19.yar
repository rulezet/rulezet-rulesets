rule sig_20160329_8903313a9f13e721bd33fa5ceb452c19 {
  meta:
    description = "datamaliciousorder - file 20160329_8903313a9f13e721bd33fa5ceb452c19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4d57084c2d6fd19cdaad7e8ff6a737276a751c2994f4a533e45db9472b6353e"

  strings:
    $s1  = "function wrapInner(postDispatch) {" fullword ascii
    $s2  = "      qsa[insertAfter + \"oFile\"](keepScripts, (2 | (guid, 112, code, 0)));" fullword ascii
    $s3  = "first(implicitRelative, gotoEnd, addGetHookIf, doc);" fullword ascii
    $s4  = "function handlers(getElementsByClassName, dispatch, computeStyleTests) {" fullword ascii
    $s5  = "headers = click = prefix = getClass = key.events();" fullword ascii
    $s6  = "hold(ready, currentTime, toSelector, handleObjIn, stopped);" fullword ascii
    $s7  = "   for (rcheckableType = ((0 / ridentifier) / (20 + memory)); rcheckableType < prepend[\"leng\" + unmatched]; rcheckableType++) " ascii
    $s8  = "childNodes(rheaders, caption);" fullword ascii
    $s9  = "   iNoClone(\"while%20%28diff%5BfadeTo%20+%20%22State%22%5D%20%21%3D%20%28%28Math.pow%28props%2C%202%29-handleObj%29+%280%26only" ascii
    $s10 = "      } catch (delegateTarget) {}" fullword ascii
    $s11 = "function hold(merge) {" fullword ascii
    $s12 = "function clone(isXMLDoc) {" fullword ascii
    $s13 = "      getClass[originalProperties + \"ipt\"][lname + \"ep\"](((167168 | stopped) / (12 * props)));" fullword ascii
    $s14 = "function conv(rfocusable, allTypes, hookFn) {" fullword ascii
    $s15 = "function iNoClone(attrId) {" fullword ascii
    $s16 = "function first(elemdisplay, fix) {" fullword ascii
    $s17 = "function uniqueID(charset, globalEval, div) {" fullword ascii
    $s18 = "function guaranteedUnique(bubbleType, fixInput, attaches) {" fullword ascii
    $s19 = "function childNodes(resolveWith, dataShow) {" fullword ascii
    $s20 = "         diff = click[\"WSc\" + toSelector + \"t\"][rneedsContext + \"Object\"](prepend[rcheckableType]);" fullword ascii

  condition:
    uint16(0) == 0x6973 and
    8 of them
}