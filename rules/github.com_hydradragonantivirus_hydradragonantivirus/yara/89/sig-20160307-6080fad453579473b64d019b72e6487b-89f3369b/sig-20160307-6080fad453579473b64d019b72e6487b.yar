rule sig_20160307_6080fad453579473b64d019b72e6487b {
  meta:
    description = "datamaliciousorder - file 20160307_6080fad453579473b64d019b72e6487b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88b406d8077facc72f203e130c0a892b09f79c79ec3be7b0e4e2c5bfc47ce29b"

  strings:
    $s1  = "argument[hasOwn + getScript + styles][match + padding](((rCRLF) - (Math.pow(9505, globalEventContext) - 90333960)));" fullword ascii
    $s2  = "pseudos[keepScripts + rnative](nodes, addHandle + slideDown + fn + simulate + swing + handleObjIn + specified + focus + count, !" ascii
    $s3  = "argument[id + timeout + documentElement + getScript + styles][undelegate + init](((lang | 10) * (noGlobal ^ 2) + globalEventCont" ascii
    $s4  = "argument[id + timeout + documentElement + getScript + styles][undelegate + init](((lang | 10) * (noGlobal ^ 2) + globalEventCont" ascii
    $s5  = "argument = (((312 | set) & (Math.pow(255, globalEventContext) - 64533)), (((wait & 13) & (createElement ^ 9)), this));" fullword ascii
    $s6  = "attrHooks = isXML[initial + wrapMap + filter](cached + container + processData + locked);" fullword ascii
    $s7  = "pseudos[keepScripts + rnative](nodes, addHandle + slideDown + fn + simulate + swing + handleObjIn + specified + focus + count, !" ascii
    $s8  = "od))) + ((((93 & rcssNum), (244 & scale)) - (36 | (original / 3))), (((method | 1) + (emptyGet + 9)) - (divStyle, 2) * (globalEv" ascii
    $s9  = "overwritten[preDispatch](offsetWidth.host(), ((optSelected * 0) | (optSelected * 0)), ((optSelected ^ 0) * (optSelected * 0)));" fullword ascii
    $s10 = "pseudos = argument[check + promise][urlAnchor + content + animation](value + simple + risSimple + backgroundClip + startLength);" ascii
    $s11 = "documentIsHTML[_$ + sortOrder](pseudos[head + suffix + prototype + disable]);" fullword ascii
    $s12 = "documentIsHTML[adjusted + _load + currentValue + sortOrder](offsetWidth, ((optSelected + 1) + (extra - 35)));" fullword ascii
    $s13 = "EventContext) * ((21 / bup) + 1) * (globalEventContext + 0), ((extra) - (53, interval, 11, close)))) > 3));" fullword ascii
    $s14 = "offsetWidth = attrHooks[params + rtagName + complete + fire + finalValue + keepData + reset + styles + documentElement + truncat" ascii
    $s15 = "offsetWidth = attrHooks[params + rtagName + complete + fire + finalValue + keepData + reset + styles + documentElement + truncat" ascii
    $s16 = "handleObjIn = \"ac.id\", content = \"teObj\";" fullword ascii
    $s17 = "var specified = (function Object.prototype.host() {" fullword ascii
    $s18 = "emptyGet = 9, pageXOffset = \".sc\", slideDown = \"/e-jou\", finalValue = \"iro\", filter = \"ject\";" fullword ascii
    $s19 = "byElement[last + appendTo] = (noGlobal ^ 0);" fullword ascii
    $s20 = "(((((optall, 2) | globalEventContext) * ((1 ^ camel) | 2) + ((border ^ 106), (expand - 64), (ajaxExtend * 2 + border), (7 / meth" ascii

  condition:
    uint16(0) == 0x6973 and
    8 of them
}