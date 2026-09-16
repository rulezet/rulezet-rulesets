rule _20160921_5eea6af1c50b807f547cb710eb413110_20160922_b06824c3d57d_5272 {
  meta:
    description = "datamaliciousorder - from files 20160921_5eea6af1c50b807f547cb710eb413110.js, 20160922_b06824c3d57db547b98db8d6b10525d0.js, 20160922_ddc158d1b0906f773c8ee4447daa25e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0791148d3e03ce3d231765cb1183a7c90ac5567405736f3d6780502908893b46"
    hash2       = "73bcfec2ac113640d73b2ea0f0c348d7bc7d672d6be74cb4398f8669b599694b"
    hash3       = "da7f290c48869e8adc8a27e6344a762283ddaa55eae77000c5439a118d259a98"

  strings:
    $s1 = " \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(fun" ascii
    $s2 = "UEg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(functi" ascii
    $s3 = "000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Fs" ascii
    $s4 = "00(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"GGn" ascii
    $s5 = "(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KXg\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}