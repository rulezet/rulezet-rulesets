rule _20160921_4787695fef4453a16be881bbe0f96c1a_20160922_e3f5fbc84de1_2925 {
  meta:
    description = "datamaliciousorder - from files 20160921_4787695fef4453a16be881bbe0f96c1a.js, 20160922_e3f5fbc84de17ad7f507fc3f34b8151f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a11e3d64ee2711e84433d2b8035ce0dafbcffa760c2026e3cfe9ba310008f90"
    hash2       = "f0d0a0daceb43d9d9a2f5d51fcc03568ed541f8699acb8b17ce2131c29f14abf"

  strings:
    $s1 = "nction f000(){return \"Br\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"HJm\";})(),(function f000(){retur" ascii
    $s2 = "tion f000(){return \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return" ascii
    $s3 = "tion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return" ascii
    $s4 = "nction f000(){return \"Nv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"WIj\";})(),(function f000(){retu" ascii
    $s5 = "return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})" ascii
    $s6 = "\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function " ascii
    $s7 = "b\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Rh\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}