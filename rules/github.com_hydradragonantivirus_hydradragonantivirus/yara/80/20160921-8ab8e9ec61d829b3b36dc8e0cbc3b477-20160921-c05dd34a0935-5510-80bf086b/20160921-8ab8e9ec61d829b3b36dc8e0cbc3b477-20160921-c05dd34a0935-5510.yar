rule _20160921_8ab8e9ec61d829b3b36dc8e0cbc3b477_20160921_c05dd34a0935_5510 {
  meta:
    description = "datamaliciousorder - from files 20160921_8ab8e9ec61d829b3b36dc8e0cbc3b477.js, 20160921_c05dd34a09358454c56b9c248f1d0304.js, 20160921_cdeac57ac549120611856c7af0c490f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6302a5443fa0c0309aa33e24b90ed81d05258a2a800cda52321e903fc44e0494"
    hash2       = "e330ec83e6ac964ffd679e6589494a6108e1995f570c539dee7b1be30953f8a3"
    hash3       = "53694193718c2cb2f90fada2d6a11f07ab2c3f8451a0f41ae580b87a142e212e"

  strings:
    $s1 = "})(),(function f000(){return \"Tb\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000" ascii
    $s2 = " f000(){return \"SEo\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s3 = "urn \"YTp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s4 = "{return \"RVb\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Tb\";})(" ascii
    $s5 = "n\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"ZFe\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}