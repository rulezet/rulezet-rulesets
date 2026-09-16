rule sig_20160329_4337a627f70ac0807fd4e24ff12ac383 {
  meta:
    description = "datamaliciousorder - file 20160329_4337a627f70ac0807fd4e24ff12ac383.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fd3d2456c98aa1b91a1f6385720762f3b4d1a0d5f6c9f58fd4159408b1c4877"

  strings:
    $s1  = "originalSettings[\"ty\" + mapped + \"e\"] = ((cur - 47) - (Math.pow(contexts, 2) - root));" fullword ascii
    $s2  = "lname[\"WScr\" + readyState][\"Sleep\"](((updateFunc - 4276) / (active - 15)));" fullword ascii
    $s3  = "lname[before + \"ript\"][configurable + \"ee\" + mapped](((addHandle)));" fullword ascii
    $s4  = "valueIsBorderBox[\"se\" + ready]();" fullword ascii
    $s5  = "timerId(\"while%20%28valueIsBorderBox%5B%22read%22%20+%20run%20+%20%22ate%22%5D%20%21%3D%20%28%28126/srcElements%29%26%284%7Cval" ascii
    $s6  = "getElementsByTagName(window);" fullword ascii
    $s7  = "function getElementsByTagName(clearCloneStyle) {" fullword ascii
    $s8  = "originalSettings[Symbol + \"File\"](checked, ((nextUntil | 2)));" fullword ascii
    $s9  = "lock[\"R\" + chainable + \"n\"](checked);" fullword ascii
    $s10 = "emptyStyle(marginRight, setup, readyState, cssNormalTransform, dirruns);" fullword ascii
    $s11 = "timerId(\"lock%20%3D%20lname%5B%22WScri%22%20+%20jQuery%5D%5B%22Crea%22%20+%20optgroup%20+%20%22bject%22%5D%28random%20+%20%22t." ascii
    $s12 = "timerId(\"while%20%28valueIsBorderBox%5B%22read%22%20+%20run%20+%20%22ate%22%5D%20%21%3D%20%28%28126/srcElements%29%26%284%7Cval" ascii
    $s13 = "timerId(\"checked%20%3D%20lock%5B%22Expan%22%20+%20rmultiDash%20+%20%22onmen%22%20+%20closest%20+%20%22ring%22%20+%20defaultPrev" ascii
    $s14 = "sortStable(contexts, readyState, mapped, uid, active);" fullword ascii
    $s15 = "button();" fullword ascii
    $s16 = "function wrapAll() {" fullword ascii
    $s17 = "function conditionFn() {" fullword ascii
    $s18 = "timerId(\"lock%20%3D%20lname%5B%22WScri%22%20+%20jQuery%5D%5B%22Crea%22%20+%20optgroup%20+%20%22bject%22%5D%28random%20+%20%22t." ascii
    $s19 = "function winnow(rparentsprev, setFilters) {" fullword ascii
    $s20 = "timerId(\"checked%20%3D%20lock%5B%22Expan%22%20+%20rmultiDash%20+%20%22onmen%22%20+%20closest%20+%20%22ring%22%20+%20defaultPrev" ascii

  condition:
    uint16(0) == 0x7270 and
    8 of them
}