rule _20160921_5ac6ab74e4b06b9e82f957e9e7bf6669_20160921_cdeac57ac549_2982 {
  meta:
    description = "datamaliciousorder - from files 20160921_5ac6ab74e4b06b9e82f957e9e7bf6669.js, 20160921_cdeac57ac549120611856c7af0c490f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50225d12c51a2decb97015971f8ce72487a24a69e64ec1d12fd7f720f2320cf3"
    hash2       = "53694193718c2cb2f90fada2d6a11f07ab2c3f8451a0f41ae580b87a142e212e"

  strings:
    $s1 = "tion f000(){return \"DNa\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return " ascii
    $s2 = "n \"Vj\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yi\";})(),(funct" ascii
    $s3 = "(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"SEo\";})(),(function f000(" ascii
    $s4 = "){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"DYs\";}" ascii
    $s5 = "Gn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Rh\";})(),(function" ascii
    $s6 = "\"Mc\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(funct" ascii
    $s7 = "eturn \"HJm\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"DIa\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}