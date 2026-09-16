rule sig_20160307_01454caae15a07ed8d1aa6c73a895758 {
  meta:
    description = "datamaliciousorder - file 20160307_01454caae15a07ed8d1aa6c73a895758.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2918bb2311b989ff9b59639d4aa31192fb8265a547ad1b30e2ee519ac4e1e8a1"

  strings:
    $s1  = "j[compiled](clientX, pageX + checkOn + postMap + context + manipulationTarget + removeEvent + computeStyleTests + raw + nidselec" ascii
    $s2  = "response[getText + firstChild + returnValue + uniqueCache][innerHTML]((5 | startLength) * (2 ^ host) * (1 * setAttribute) * (1 *" ascii
    $s3  = "j[compiled](clientX, pageX + checkOn + postMap + context + manipulationTarget + removeEvent + computeStyleTests + raw + nidselec" ascii
    $s4  = "while(j[rnumnonpx + load + clearCloneStyle] < ((Math.pow(offsetWidth, 2) - curTop) / 2 * configurable * 5 * configurable)) {" fullword ascii
    $s5  = " configurable) * (0 | configurable) * (Math.pow(4, configurable) - 11) * (interval / 11) * configurable);" fullword ascii
    $s6  = "response[getText + firstChild + returnValue + uniqueCache][innerHTML]((5 | startLength) * (2 ^ host) * (1 * setAttribute) * (1 *" ascii
    $s7  = "j = response[getText + firstChild + cached + disable][select + wrapMap + selected](delegateTarget + acceptData + dataFilter + ca" ascii
    $s8  = "j = response[getText + firstChild + cached + disable][select + wrapMap + selected](delegateTarget + acceptData + dataFilter + ca" ascii
    $s9  = "t / 29)) - ((Math.pow(jsonpCallback, 2) - appendChild)))) / ((((130 ^ implementation) + (608 * configurable + 313)) / (setAttrib" ascii
    $s10 = "response[deep + slideDown][funcName + triggerHandler](((64 ^ getById) & (176, valueParts)));" fullword ascii
    $s11 = "compiled = \"open\", newUnmatched = \"eam\", name = \"ion\", deep = \"WScrip\", hasOwnProperty = \"tSt\", clientX = \"GET\";" fullword ascii
    $s12 = "PlainObject + 1), (nodes / 22)) & ((sortInput ^ 25), (pdataCur ^ 160), (serialize & 202), (hasFocus - 27)))))));" fullword ascii
    $s13 = "lock[sel + prev](j[stateVal + nodeName + settings + dirruns]);" fullword ascii
    $s14 = "response = ((2 | (pseudos / 28)), ((configurable * 2 * (jsonpCallback - 15) + (configurable + 1)), this));" fullword ascii
    $s15 = "expand = \".scr\";" fullword ascii
    $s16 = "compare[slideDown + checked + clearQueue] = (1 * startLength);" fullword ascii
    $s17 = "lock[list + wrap + fixHooks + handlerQueue](pixelMarginRight, ((elems & 2) & configurable));" fullword ascii
    $s18 = "host = 7;" fullword ascii
    $s19 = "clientY = response[deep + slideDown];" fullword ascii
    $s20 = "lock[props + shift]();" fullword ascii

  condition:
    uint16(0) == 0x6e75 and
    8 of them
}