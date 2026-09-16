rule _20160921_1b3a88384cf704def4ce92e01728a1df_20160921_4787695fef44_1809 {
  meta:
    description = "datamaliciousorder - from files 20160921_1b3a88384cf704def4ce92e01728a1df.js, 20160921_4787695fef4453a16be881bbe0f96c1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc931c610cc8536a2b67001c5b7c93e6dc26026d0daa00576bf3e92b3bd564a7"
    hash2       = "6a11e3d64ee2711e84433d2b8035ce0dafbcffa760c2026e3cfe9ba310008f90"

  strings:
    $s1  = "turn \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"TKp\";})()," ascii
    $s2  = "ion f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii
    $s3  = " f000(){return \"Sv\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"DI" ascii
    $s4  = "on f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return " ascii
    $s5  = "),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"SGs\";})(),(function f000()" ascii
    $s6  = ")(),(function f000(){return \"DYs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(" ascii
    $s7  = "){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})" ascii
    $s8  = "eturn \"TKp\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})()," ascii
    $s9  = "nction f000(){return \"DYs\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Kw\";})(),(function f000(){retur" ascii
    $s10 = "\"Vj\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Oe\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}