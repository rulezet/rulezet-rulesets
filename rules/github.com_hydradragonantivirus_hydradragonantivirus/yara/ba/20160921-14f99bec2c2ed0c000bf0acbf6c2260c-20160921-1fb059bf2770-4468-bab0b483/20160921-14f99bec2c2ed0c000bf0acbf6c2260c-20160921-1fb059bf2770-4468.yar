rule _20160921_14f99bec2c2ed0c000bf0acbf6c2260c_20160921_1fb059bf2770_4468 {
  meta:
    description = "datamaliciousorder - from files 20160921_14f99bec2c2ed0c000bf0acbf6c2260c.js, 20160921_1fb059bf2770cd24354f1407193ed7c3.js, 20160921_b5e2b5a2e8f104e719b3c6631c08f1f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "224106b166fc0a998ec1d58e5d4a78c585bdeb76194d93210753d7d0f558c06b"
    hash2       = "ca19a6205a8df61781b8acbf540faa9dd7bc11338d9b2e4285541a5ac284f620"
    hash3       = "8495e7e7fc77026b5e5681ac973eefb0561cb5cce78632996de59641ce00258e"

  strings:
    $s1 = "00(){return \"KDh\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s2 = "(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"KDh\";})(),(function f000(){" ascii
    $s3 = "(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KDh\";})(),(function f000(" ascii
    $s4 = "00(){return \"HJm\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg" ascii
    $s5 = " \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}