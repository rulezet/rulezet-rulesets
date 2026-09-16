rule sig_20160325_d6317cc3b4a30c0fa9d2dba7f74f2a42 {
  meta:
    description = "datamaliciousorder - file 20160325_d6317cc3b4a30c0fa9d2dba7f74f2a42.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0700109e8a3fa16db8308cf881bcb8895419e221e3a64fc1cdf6697515dc8d14"

  strings:
    $s1  = "postFinder = getStyles[\"Expan\" + getPropertyValue + \"ron\" + implementation + \"Str\" + reverse](\"%TEMP%\" + rts) + \"on\" +" ascii
    $s2  = "postFinder = getStyles[\"Expan\" + getPropertyValue + \"ron\" + implementation + \"Str\" + reverse](\"%TEMP%\" + rts) + \"on\" +" ascii
    $s3  = "originalEvent = \"c\", getComputedStyle = \"s.exe\", condense = \"GE\", rootjQuery = 11958;" fullword ascii
    $s4  = "stopped[addGetHookIf + \"ee\" + oldCallbacks](((7979 + extend) - (88435 / compile)));" fullword ascii
    $s5  = "hasContent = 34, responseText = \"write\", getPropertyValue = \"dEnvi\", sort = 108;;" fullword ascii
    $s6  = "var width = [][\"const\" + propFix][\"prot\" + attrHooks + \"pe\"][getAttributeNode + \"rt\"][matchesSelector + \"ply\"]();" fullword ascii
    $s7  = "getStyles = stopped[\"Cre\" + guaranteedUnique + \"ject\"](deepDataAndEvents + \"ipt.Sh\" + emptyStyle);" fullword ascii
    $s8  = "module[postDispatch + \"y\" + last] = (9 / current);" fullword ascii
    $s9  = "protocol[file + \"t\"][tbody + \"ep\"](((13897 & rootjQuery) | (16273 & firingIndex)));" fullword ascii
    $s10 = "function list(newSelector, getter, elementMatchers, elems) {" fullword ascii
    $s11 = "radio(deepDataAndEvents, last, getAttributeNode);" fullword ascii
    $s12 = "return getter[elems](newSelector, elementMatchers);" fullword ascii
    $s13 = "getter[startTime](cssNormalTransform[fire]);" fullword ascii
    $s14 = "function parentOffset(fire, position, getter, startTime) {" fullword ascii
    $s15 = "stopped = load[\"WScr\" + andSelf];" fullword ascii
    $s16 = "module = new multipleContexts[\"Acti\" + hasData + \"ject\"](pos + \"DB.S\" + not);" fullword ascii
    $s17 = "compile = 23;" fullword ascii
    $s18 = "scrollTop(rootjQuery, condense);" fullword ascii
    $s19 = "var version = \"Object\"," fullword ascii
    $s20 = "copyIsArray(cors, rhash, implementation);" fullword ascii

  condition:
    uint16(0) == 0x7865 and
    8 of them
}