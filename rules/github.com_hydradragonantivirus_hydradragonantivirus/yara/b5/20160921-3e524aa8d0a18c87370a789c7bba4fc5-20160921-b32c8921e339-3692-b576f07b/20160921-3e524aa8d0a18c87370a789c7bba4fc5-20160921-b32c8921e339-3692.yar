rule _20160921_3e524aa8d0a18c87370a789c7bba4fc5_20160921_b32c8921e339_3692 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e524aa8d0a18c87370a789c7bba4fc5.js, 20160921_b32c8921e3390cb8f9450436f4e43cfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71a83b86275cb43222066a6d27dfb98cdd9fc8283b2b007f9262c38686262b9a"
    hash2       = "5ab35ff2eba15a460823fc709e29f7c1041f054096a3690e92c926943d39d6a8"

  strings:
    $s1 = "n f000(){return \"DYs\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"G" ascii
    $s2 = "\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"BQb\";})(),(function " ascii
    $s3 = "n f000(){return \"XTn\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s4 = "){return \"Yz\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})(" ascii
    $s5 = "urn \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Fs\";})(),(" ascii
    $s6 = "turn \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}