rule _20160921_cebdb99ce2e54d24acef5b8ee0096562_20160922_41319625a334_4063 {
  meta:
    description = "datamaliciousorder - from files 20160921_cebdb99ce2e54d24acef5b8ee0096562.js, 20160922_41319625a3342333693d5eefb82a43ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87071d18d308dc7717dabe03dc0d11efe7ee7231e95d9fca71e480f5f2430f7d"
    hash2       = "6cb4a85918ba85e72bd611e7820ea056409f5f25a58a8d15335e282229f10af9"

  strings:
    $s1 = "{return \"PTi\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Yi\";})(" ascii
    $s2 = ";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"TRc\";})(),(function f0" ascii
    $s3 = "RVb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Go\";})(),(functi" ascii
    $s4 = "000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"RV" ascii
    $s5 = "00(){return \"DAp\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn" ascii
    $s6 = "),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}