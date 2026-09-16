rule _20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc_20160921_331df381948e_322 {
  meta:
    description = "datamaliciousorder - from files 20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc.js, 20160921_331df381948e6d95c6a9496aeda63d16.js, 20160921_63def3fff7f150b1f60fee716b458fd6.js, 20160921_ff1932b6e91481dd80ff6251296b57fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1db38abaeb5bf0ea6f5b5ff0f4a9eedd9ce90cd62e2966ce8936e8e8fbc2905"
    hash2       = "74d3e5ca6efd3e26128cb4a5ab3009003c70f505b353304608d74dfd028df0d7"
    hash3       = "85e2ab59983c4c704998f4c7c577cd8211e7b590b3f200f88616fe64954c10ea"
    hash4       = "07e5271d8517f89575dc2737fae5e8da89c7f2f25cd40c68e183d826da6b2bf0"

  strings:
    $s1  = "00(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"PTi\"" ascii
    $s2  = "urn \"PTs\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s3  = "){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Yi\";})(" ascii
    $s4  = "000(){return \"Sj\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\"" ascii
    $s5  = "})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Yi\";})(),(function f000" ascii
    $s6  = "ion f000(){return \"EZu\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Qa\";})(),(function f000(){return " ascii
    $s7  = "eturn \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"TKp\";})(" ascii
    $s8  = "function f000(){return \"Br\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Nv\";})(),(function f000(){ret" ascii
    $s9  = "000(){return \"SEo\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s10 = ",(function f000(){return \"Uo\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Uo\";})(),(function f000(){re" ascii
    $s11 = "function f000(){return \"Uo\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Tn\";})(),(function f000(){retu" ascii
    $s12 = "){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})()" ascii
    $s13 = "tion f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return " ascii
    $s14 = ";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s15 = "{return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"MBb\";})(" ascii
    $s16 = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BMj\";})(),(function f000(){retu" ascii
    $s17 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"HJm\";})(),(function f000(){ret" ascii
    $s18 = "\"Oe\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s19 = "eturn \"Lp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s20 = "turn \"Br\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Br\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}