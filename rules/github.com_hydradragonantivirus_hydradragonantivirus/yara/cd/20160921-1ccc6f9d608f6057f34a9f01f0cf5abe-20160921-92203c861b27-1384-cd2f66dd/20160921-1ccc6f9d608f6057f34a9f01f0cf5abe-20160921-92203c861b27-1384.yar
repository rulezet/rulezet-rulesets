rule _20160921_1ccc6f9d608f6057f34a9f01f0cf5abe_20160921_92203c861b27_1384 {
  meta:
    description = "datamaliciousorder - from files 20160921_1ccc6f9d608f6057f34a9f01f0cf5abe.js, 20160921_92203c861b27f106aadc39fdc2b4c6b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "226d26c073abdcaab4155bb0b8d789289cf0a453f58c9f6383385cc78660a27e"
    hash2       = "307c62eb5d0e72645486ed8ab490a017889f28cb40d74f607fae031e9ef250fb"

  strings:
    $s1  = " \"IPu\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(fun" ascii
    $s2  = "f000(){return \"PTs\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GG" ascii
    $s3  = "turn \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(" ascii
    $s4  = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"PTi\";})(),(function f000" ascii
    $s5  = "\"EZu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"OMd\";})(),(func" ascii
    $s6  = "0(){return \"Mc\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"PTs\"" ascii
    $s7  = "urn \"Wy\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(f" ascii
    $s8  = "n f000(){return \"Qa\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s9  = "f000(){return \"Oh\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Do\"" ascii
    $s10 = ")(),(function f000(){return \"DYs\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BQb\";})(),(function f00" ascii
    $s11 = ")(),(function f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"OMd\";})(),(function f000" ascii
    $s12 = " f000(){return \"Do\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"M" ascii
    $s13 = "\"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"SEo\";})(),(func" ascii
    $s14 = "),(function f000(){return \"MDb\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"TKp\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}