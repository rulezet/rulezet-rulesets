rule _20160921_220036ca1d4152e6bd72a833a4b3f832_20160922_99c635a67f89_3520 {
  meta:
    description = "datamaliciousorder - from files 20160921_220036ca1d4152e6bd72a833a4b3f832.js, 20160922_99c635a67f8963210ce99c7a8cf9cd6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54f3e02c5b6d4d5d2db9a8d86252256d2f355ce582a09c9d870f84a9047c47ff"
    hash2       = "c5b5cdc3be24f457939814321b7f3397a8f4d2370b1e57cdae1f3f10537e562c"

  strings:
    $s1 = "000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn" ascii
    $s2 = "ion f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"BQb\";})(),(function f000(){return " ascii
    $s3 = "nction f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";})(),(function f000(){ret" ascii
    $s4 = "return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"TRc\";})(" ascii
    $s5 = "),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"EZu\";})(),(function f000(" ascii
    $s6 = "ction f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}