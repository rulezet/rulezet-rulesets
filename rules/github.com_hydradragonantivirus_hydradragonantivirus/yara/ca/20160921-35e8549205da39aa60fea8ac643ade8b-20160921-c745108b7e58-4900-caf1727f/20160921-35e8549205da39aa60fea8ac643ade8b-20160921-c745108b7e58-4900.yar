rule _20160921_35e8549205da39aa60fea8ac643ade8b_20160921_c745108b7e58_4900 {
  meta:
    description = "datamaliciousorder - from files 20160921_35e8549205da39aa60fea8ac643ade8b.js, 20160921_c745108b7e58564d28687f6e180c98c5.js, 20160921_d74d6a32efd0c1fd568c81769c75b5f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe7319f5e948bc89c8a5f42f117ed0667b1816e94f61d88225df2d217cf74b06"
    hash2       = "933f7e4ee0e09bde34704852e63df99ed6341ecadbe6b7afc2244b8228048418"
    hash3       = "eeb2c0427dff61d2dceedf890b96f76da6a37634fefa03079a481c476d7a3547"

  strings:
    $s1 = " \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(funct" ascii
    $s2 = "000(){return \"Yz\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tn\"" ascii
    $s3 = "{return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Fs\";})" ascii
    $s4 = "ction f000(){return \"XTn\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s5 = "n f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"K" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}