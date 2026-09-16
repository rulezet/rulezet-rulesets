rule _20160921_3941d41b2f7cb84a9ce802558f71cf2e_20160921_4aeb02b393c6_3650 {
  meta:
    description = "datamaliciousorder - from files 20160921_3941d41b2f7cb84a9ce802558f71cf2e.js, 20160921_4aeb02b393c6ed3fdeadcb6a29499bfc.js, 20160922_e3f5fbc84de17ad7f507fc3f34b8151f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af803579fff33b5e316911dc121155eb553434eec287816287bbd86b427b3f7f"
    hash2       = "8899077a1617372e22229a59750fc04d1c9a0b2a1176b97742c5d76576a2edb1"
    hash3       = "f0d0a0daceb43d9d9a2f5d51fcc03568ed541f8699acb8b17ce2131c29f14abf"

  strings:
    $s1 = "})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function f000(" ascii
    $s2 = "ction f000(){return \"WIj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return" ascii
    $s3 = "turn \"OUx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qj\";})(),(f" ascii
    $s4 = "urn \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(" ascii
    $s5 = "n \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(fun" ascii
    $s6 = "eturn \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}