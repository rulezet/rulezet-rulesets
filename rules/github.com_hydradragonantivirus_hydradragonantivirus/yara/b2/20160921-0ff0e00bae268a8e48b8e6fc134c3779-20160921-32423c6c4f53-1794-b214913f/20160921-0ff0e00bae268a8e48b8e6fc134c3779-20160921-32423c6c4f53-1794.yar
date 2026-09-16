rule _20160921_0ff0e00bae268a8e48b8e6fc134c3779_20160921_32423c6c4f53_1794 {
  meta:
    description = "datamaliciousorder - from files 20160921_0ff0e00bae268a8e48b8e6fc134c3779.js, 20160921_32423c6c4f53c5e0240449620e4b98c9.js, 20160921_3974cbb8b2af1f98b68ab31621da93d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f9f30b45066ff23899a854b2ef766240b2becea05223ad11c6bf5cde97c3048"
    hash2       = "1627aa0e729ffe8aba0e7faa8a6286c25a744600e193b72dbc3254fcc98a6003"
    hash3       = "707fba854060aa6294a0cf0c11b8eed992c56785375920bc41b7e95f514ab760"

  strings:
    $s1  = "0(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";" ascii
    $s2  = "){return \"PTi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lp\";}" ascii
    $s3  = "nction f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return" ascii
    $s4  = "b\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"PTs\";})(),(function" ascii
    $s5  = "0(){return \"TKl\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Go\"" ascii
    $s6  = "MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s7  = "turn \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Vu\";})(),(" ascii
    $s8  = "ction f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return" ascii
    $s9  = " \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fun" ascii
    $s10 = "f000(){return \"Km\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yz\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}