rule _20160921_25c11e2eab44b5e0380e0bd805a72790_20160921_35e8549205da_3545 {
  meta:
    description = "datamaliciousorder - from files 20160921_25c11e2eab44b5e0380e0bd805a72790.js, 20160921_35e8549205da39aa60fea8ac643ade8b.js, 20160921_c745108b7e58564d28687f6e180c98c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "912d9aec3079fb6a2e4f83d3826286707a52a653de6ec6eede9711d5b416a790"
    hash2       = "fe7319f5e948bc89c8a5f42f117ed0667b1816e94f61d88225df2d217cf74b06"
    hash3       = "933f7e4ee0e09bde34704852e63df99ed6341ecadbe6b7afc2244b8228048418"

  strings:
    $s1 = "function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){re" ascii
    $s2 = "000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJ" ascii
    $s3 = "0(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"PTi" ascii
    $s4 = "0(){return \"QDg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";" ascii
    $s5 = " \"Um\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s6 = "GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"TRc\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}