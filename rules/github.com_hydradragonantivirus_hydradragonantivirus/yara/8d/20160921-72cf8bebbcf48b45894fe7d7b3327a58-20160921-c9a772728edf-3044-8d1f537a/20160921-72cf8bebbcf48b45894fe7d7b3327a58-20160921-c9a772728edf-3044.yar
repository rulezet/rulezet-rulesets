rule _20160921_72cf8bebbcf48b45894fe7d7b3327a58_20160921_c9a772728edf_3044 {
  meta:
    description = "datamaliciousorder - from files 20160921_72cf8bebbcf48b45894fe7d7b3327a58.js, 20160921_c9a772728edf4eeff48c1aea32c00a13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "004799df77a97e1e1816f6a4a1acf9bec5dfd13ae07613832796a6c9ef0cc578"
    hash2       = "76f52cefe2f1cf5954919532ecd1ec4c5c9072cb4edc435169d570baa9894ed9"

  strings:
    $s1 = "{return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Oh\";})(" ascii
    $s2 = "turn \"Km\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"NBs\";})(),(" ascii
    $s3 = ";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";})(),(function f0" ascii
    $s4 = "ion f000(){return \"Lo\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return " ascii
    $s5 = "unction f000(){return \"Yi\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f000(){retu" ascii
    $s6 = "})(),(function f000(){return \"Do\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f00" ascii
    $s7 = "n\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"IAa\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}