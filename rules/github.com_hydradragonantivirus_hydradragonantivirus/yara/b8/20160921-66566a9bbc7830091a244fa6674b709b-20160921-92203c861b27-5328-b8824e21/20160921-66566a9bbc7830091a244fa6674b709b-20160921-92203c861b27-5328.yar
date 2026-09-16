rule _20160921_66566a9bbc7830091a244fa6674b709b_20160921_92203c861b27_5328 {
  meta:
    description = "datamaliciousorder - from files 20160921_66566a9bbc7830091a244fa6674b709b.js, 20160921_92203c861b27f106aadc39fdc2b4c6b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "154f7ca38a058d2590f40ec43ada530305244e5c7e86bbedd19aa9c0e1ca02aa"
    hash2       = "307c62eb5d0e72645486ed8ab490a017889f28cb40d74f607fae031e9ef250fb"

  strings:
    $s1 = "ion f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Um\";})(),(function f000(){return " ascii
    $s2 = "(function f000(){return \"WIj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZIi\";})(),(function f000(){r" ascii
    $s3 = "s\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function" ascii
    $s4 = "(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZIi\";}" ascii
    $s5 = "Ij\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"EZu\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}