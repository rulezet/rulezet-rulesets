rule _20160921_0ff0e00bae268a8e48b8e6fc134c3779_20160921_a3256642bcc1_4382 {
  meta:
    description = "datamaliciousorder - from files 20160921_0ff0e00bae268a8e48b8e6fc134c3779.js, 20160921_a3256642bcc1ce0dfec8677fe62bc590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f9f30b45066ff23899a854b2ef766240b2becea05223ad11c6bf5cde97c3048"
    hash2       = "4af9ef65888b7e1a452f74c901f68872403712ef67ed9f79ac51c3bfb98c1f59"

  strings:
    $s1 = " \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Go\";})(),(func" ascii
    $s2 = "tion f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Go\";})(),(function f000(){return " ascii
    $s3 = "000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Lo" ascii
    $s4 = " \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(func" ascii
    $s5 = " \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}