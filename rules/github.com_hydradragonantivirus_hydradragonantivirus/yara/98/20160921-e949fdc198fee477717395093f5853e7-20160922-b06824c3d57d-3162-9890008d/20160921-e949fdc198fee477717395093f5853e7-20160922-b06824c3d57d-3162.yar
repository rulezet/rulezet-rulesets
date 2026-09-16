rule _20160921_e949fdc198fee477717395093f5853e7_20160922_b06824c3d57d_3162 {
  meta:
    description = "datamaliciousorder - from files 20160921_e949fdc198fee477717395093f5853e7.js, 20160922_b06824c3d57db547b98db8d6b10525d0.js, 20160922_ddc158d1b0906f773c8ee4447daa25e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ff56149c45e72e300c579a750f7d49b8e0e723f75bb7a74343267578dd71a4d"
    hash2       = "73bcfec2ac113640d73b2ea0f0c348d7bc7d672d6be74cb4398f8669b599694b"
    hash3       = "da7f290c48869e8adc8a27e6344a762283ddaa55eae77000c5439a118d259a98"

  strings:
    $s1 = "ion f000(){return \"YTp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return" ascii
    $s2 = "000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn" ascii
    $s3 = "n\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s4 = "0(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Wy\";}" ascii
    $s5 = "urn \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Wy\";})(),(f" ascii
    $s6 = "(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";}" ascii
    $s7 = "{return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sv\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}