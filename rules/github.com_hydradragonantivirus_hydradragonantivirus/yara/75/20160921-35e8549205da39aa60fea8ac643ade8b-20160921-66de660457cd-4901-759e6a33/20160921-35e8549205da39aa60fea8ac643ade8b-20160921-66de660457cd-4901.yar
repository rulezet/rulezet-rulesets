rule _20160921_35e8549205da39aa60fea8ac643ade8b_20160921_66de660457cd_4901 {
  meta:
    description = "datamaliciousorder - from files 20160921_35e8549205da39aa60fea8ac643ade8b.js, 20160921_66de660457cd1dcbe458e50b91bafaca.js, 20160921_c745108b7e58564d28687f6e180c98c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe7319f5e948bc89c8a5f42f117ed0667b1816e94f61d88225df2d217cf74b06"
    hash2       = "0c92eafe23596e161cf04cc6206b7e5cac5dafb3ce36772cc5a8a4f0f827211c"
    hash3       = "933f7e4ee0e09bde34704852e63df99ed6341ecadbe6b7afc2244b8228048418"

  strings:
    $s1 = "ion f000(){return \"OUx\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return " ascii
    $s2 = "{return \"MMz\";})(),(function f000(){return \"MKa\";})()];" fullword ascii
    $s3 = "){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";" ascii
    $s4 = "urn \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(f" ascii
    $s5 = "nction f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}