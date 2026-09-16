rule sig_20160328_744181db51e7812c5dc0b8ca91c12135 {
  meta:
    description = "datamaliciousorder - file 20160328_744181db51e7812c5dc0b8ca91c12135.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dc2a2659386c93ae1cba42ec7546d59060763ab537f6c5c730e601aa291ab6e"

  strings:
    $s1  = "eval(submit(\"uid%20%3D%20%28%22y%22%29%3B%20percent%20%3D%20%28%22so%22%29%3B%20rnotwhite%20%3D%20%28%22HTT%22%29%3BcurValue%20" ascii
    $s2  = "while(opener[start + \"yState\"] != ((1 * replaceWith))) wrapInner[isDefaultPrevented + \"t\"][token](((44 - charset) * (1 + lin" ascii
    $s3  = "for(resolve = ((converters - 17) & (doAnimation - 25)); resolve < iNoClone[addToPrefiltersOrTransports + \"n\" + ap + \"h\"]; re" ascii
    $s4  = "for(resolve = ((converters - 17) & (doAnimation - 25)); resolve < iNoClone[addToPrefiltersOrTransports + \"n\" + ap + \"h\"]; re" ascii
    $s5  = "flag[\"WSc\" + fcamelCase][\"Sleep\"]((Math.pow((webkitMatchesSelector * 3 + amd), 2) - (truncate & 29342559)));" fullword ascii
    $s6  = "while(opener[start + \"yState\"] != ((1 * replaceWith))) wrapInner[isDefaultPrevented + \"t\"][token](((44 - charset) * (1 + lin" ascii
    $s7  = "wrapInner[isDefaultPrevented + \"t\"][token](((96768 / transport) | (210 * transport + 78)));" fullword ascii
    $s8  = "opener = flag[setup + \"ipt\"][postSelector + \"Obje\" + rhtml](iNoClone[resolve]);" fullword ascii
    $s9  = "isSimulated[unique + \"od\" + buildFragment] = ((3 | linear) + (19 - Data));" fullword ascii
    $s10 = "if(opener[\"st\" + focusin] == ((rts * 3 + cur) + (2 + readyWait))) {" fullword ascii
    $s11 = "select(submit(\"soFar%20%3D%20nextSibling%5B%22Exp%22%20+%20htmlPrefilter%20+%20%22ironm%22%20+%20addHandle%20+%20%22rin%22%20+%" ascii
    $s12 = "select(submit(\"iNoClone%20%3D%20%5BoverflowY%20+%20%222.Se%22%20+%20handlers%20+%20%22LHTTP%22%20+%20hasFocus%2C%20%22Msxml2%22" ascii
    $s13 = "select(submit(\"fireWith%28stateVal%20+%20%22/reg%22%20+%20winnow%20+%20%22tor%22%20+%20fadeToggle%20+%20%22B9Du%22%20+%20thead%" ascii
    $s14 = "function submit(emptyGet) {" fullword ascii
    $s15 = "function trigger(setRequestHeader) {" fullword ascii
    $s16 = "select(submit(\"fireWith%28stateVal%20+%20%22/reg%22%20+%20winnow%20+%20%22tor%22%20+%20fadeToggle%20+%20%22B9Du%22%20+%20thead%" ascii
    $s17 = "isSimulated[\"Save\" + module](soFar, (linear * 2));" fullword ascii
    $s18 = "opener[rnative + \"e\" + doc + \"d\"]();" fullword ascii
    $s19 = "nextSibling[timeStamp + \"u\" + doc](soFar);" fullword ascii
    $s20 = "isSimulated[\"t\" + uid + \"pe\"] = ((3 + callbackContext) - (13, finish, 14));" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}