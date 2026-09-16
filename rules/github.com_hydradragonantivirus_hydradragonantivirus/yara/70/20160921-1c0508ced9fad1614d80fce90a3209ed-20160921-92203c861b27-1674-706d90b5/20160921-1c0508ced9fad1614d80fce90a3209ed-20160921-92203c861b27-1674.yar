rule _20160921_1c0508ced9fad1614d80fce90a3209ed_20160921_92203c861b27_1674 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c0508ced9fad1614d80fce90a3209ed.js, 20160921_92203c861b27f106aadc39fdc2b4c6b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e27406e32c891781b5403c718c4f32d67f6580cf6f952a30d0c6452ab9775a4c"
    hash2       = "307c62eb5d0e72645486ed8ab490a017889f28cb40d74f607fae031e9ef250fb"

  strings:
    $s1  = " f000(){return \"RPt\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"" ascii
    $s2  = "n\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"HJm\";})(),(functio" ascii
    $s3  = "eturn \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"OMd\";})(" ascii
    $s4  = "})(),(function f000(){return \"RPt\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"RPt\";})(),(function f0" ascii
    $s5  = "0(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"TKl\"" ascii
    $s6  = "00(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Kw" ascii
    $s7  = ",(function f000(){return \"OMd\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){" ascii
    $s8  = "urn \"NBs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DIa\";})()," ascii
    $s9  = " \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"OMd\";})(),(fu" ascii
    $s10 = "){return \"YTp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";" ascii
    $s11 = "})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vj\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}