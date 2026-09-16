rule _20160921_37277908f8111ad292e17a84927fe01d_20160922_e3f5fbc84de1_1838 {
  meta:
    description = "datamaliciousorder - from files 20160921_37277908f8111ad292e17a84927fe01d.js, 20160922_e3f5fbc84de17ad7f507fc3f34b8151f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cac56e804b2f49b3fcd9bbc13fbdc4deb3a0ef68848e6527c15ab41f1104f286"
    hash2       = "f0d0a0daceb43d9d9a2f5d51fcc03568ed541f8699acb8b17ce2131c29f14abf"

  strings:
    $s1  = "on f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return " ascii
    $s2  = ")(),(function f000(){return \"SEo\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"YTp\";})(),(function f00" ascii
    $s3  = "(){return \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Oh\";}" ascii
    $s4  = "n f000(){return \"MBb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"YTp\";})(),(function f000(){return " ascii
    $s5  = "ion f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"RLk\";})(),(function f000(){return" ascii
    $s6  = ";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Sv\";})(),(function f0" ascii
    $s7  = "urn \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"TRc\";})(),(f" ascii
    $s8  = "return \"Go\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})()" ascii
    $s9  = "\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"TRc\";})(),(function " ascii
    $s10 = "ion f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DYs\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}