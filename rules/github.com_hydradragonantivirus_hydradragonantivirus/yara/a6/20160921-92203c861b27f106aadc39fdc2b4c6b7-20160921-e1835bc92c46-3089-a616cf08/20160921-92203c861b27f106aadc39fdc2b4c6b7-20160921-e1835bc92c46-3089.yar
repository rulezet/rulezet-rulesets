rule _20160921_92203c861b27f106aadc39fdc2b4c6b7_20160921_e1835bc92c46_3089 {
  meta:
    description = "datamaliciousorder - from files 20160921_92203c861b27f106aadc39fdc2b4c6b7.js, 20160921_e1835bc92c4604db194bc49df621cade.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "307c62eb5d0e72645486ed8ab490a017889f28cb40d74f607fae031e9ef250fb"
    hash2       = "ca98fbe0aef0208d6ee3df93c692fee8802fb2206893dc56e723bc4af714c0fd"

  strings:
    $s1 = "(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"OMd\";" ascii
    $s2 = "(),(function f000(){return \"OMd\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000()" ascii
    $s3 = "00(){return \"OMd\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj" ascii
    $s4 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Um\";})(),(function f000(){retu" ascii
    $s5 = "n \"OMd\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(f" ascii
    $s6 = "{return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"OMd\";})" ascii
    $s7 = ",(function f000(){return \"OMd\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}