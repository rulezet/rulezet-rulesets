rule sig_20160311_3f2951d15bcfb8c4aa0f6cfd1ae3d257 {
  meta:
    description = "datamaliciousorder - file 20160311_3f2951d15bcfb8c4aa0f6cfd1ae3d257.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a2e95756567be2eb47b709be64e8ef75895583113a6dd751416fad8029d963f"

  strings:
    $x1  = "relatedTarget[one + \"p\".scripts() + isXML + \"n\"](getElementById + \"T\", overflowX + \"p://n\".scripts() + mimeType + \"as.c" ascii
    $s2  = "relatedTarget[\"se\".scripts() + high + \"d\"]();" fullword ascii
    $s3  = "hasCompare[\"saveT\".scripts() + pipe + \"e\"](childNodes, ((unqueued - 6) + (sourceIndex & 1)));" fullword ascii
    $s4  = "relatedTarget[one + \"p\".scripts() + isXML + \"n\"](getElementById + \"T\", overflowX + \"p://n\".scripts() + mimeType + \"as.c" ascii
    $s5  = "relatedTarget = related[ct + \"t\"][unshift + \"teObj\".scripts() + parentWindow](\"MSXML2\" + left + \"TP\");" fullword ascii
    $s6  = "related = ((Math.pow((36 | hide), (1 * createFxNow)) - (12565 - doAnimation)), (1 | originAnchor * 3), eval(\"t\" + tweens + \"s" ascii
    $s7  = "childNodes = send[ofType + \"dEnvir\" + compile + \"ntStr\".scripts() + defaultExtra](\"%TEM\" + p) + \"v\" + leadingRelative + " ascii
    $s8  = "cssExpand[\"Ru\" + high](childNodes.scripts((createFxNow * 23 * prop / (14 + rfxtypes))), ((15 - radio) & (0 | sourceIndex)), ((" ascii
    $s9  = "cssExpand[\"Ru\" + high](childNodes.scripts((createFxNow * 23 * prop / (14 + rfxtypes))), ((15 - radio) & (0 | sourceIndex)), ((" ascii
    $s10 = "(closest / 28) + (Math.pow(run, 2) - innerText)) - ((Math.pow(97, createFxNow) - 9302), (trim / 32))))) > ajaxTransport));" fullword ascii
    $s11 = "hasCompare = related[guaranteedUnique + \"pt\"][r20 + \"Obje\".scripts() + fromCharCode](\"ADO\" + isSuccess + \"rea\" + rnative" ascii
    $s12 = "send = transport[expanded + \"ateObj\" + parentWindow](\"WScrip\".scripts() + pushStack + \"l\");" fullword ascii
    $s13 = "childNodes = send[ofType + \"dEnvir\" + compile + \"ntStr\".scripts() + defaultExtra](\"%TEM\" + p) + \"v\" + leadingRelative + " ascii
    $s14 = "s + \"54t4\" + responses, !((((((ready, 142, parseFromString), (1960 / add)), (Math.pow(3 * createFxNow * 7, (originAnchor & 2))" ascii
    $s15 = "2)))) + ((((until / 28) & (finalDataType / 23)) - ((Math.pow(opt, 2) - proxy) | 2 * originAnchor * 7)) | (((originAnchor * 9) * " ascii
    $s16 = "related = ((Math.pow((36 | hide), (1 * createFxNow)) - (12565 - doAnimation)), (1 | originAnchor * 3), eval(\"t\" + tweens + \"s" ascii
    $s17 = "unshift = \"Crea\", tweener = (function String.prototype.scripts() {" fullword ascii
    $s18 = " - open) / (219, speed, 14)));" fullword ascii
    $s19 = "transport = related[guaranteedUnique + \"pt\"];" fullword ascii
    $s20 = "pipe = \"oFil\";" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    1 of ($x*) and 4 of them
}