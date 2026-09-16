rule _20160921_1f7d568f432abb102bc2d5dbd6c68c22_20160921_69015d5cf863_4636 {
  meta:
    description = "datamaliciousorder - from files 20160921_1f7d568f432abb102bc2d5dbd6c68c22.js, 20160921_69015d5cf863b10983b8aa49b42d835e.js, 20160921_8b27f7688489936aa1cc7fded52f4a64.js, 20160921_c54afc417f4f2e6afc93a834c28784f2.js, 20160921_d57bd7101328f2bbf1f061a7dab83490.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "193a02aff0ca7f757ef6d01358baac9c7338cd556144a08982dce9382eff6344"
    hash2       = "797bada2609e8fc67a8ede267e9fcce2fc817f630e6fe62c7953cc722eea6d2c"
    hash3       = "dbf2fa1deb81fd17a55e884848d77b2d3c5d766fed0005f738840703aa8a9dda"
    hash4       = "20ec6b05e6f9287e0487d83e2fe14d9d0ca6d013f0a0ee7abade9f2b0b6268d5"
    hash5       = "fa72df41c05c5483fee755296c5d2da37c5e14a015c2aac82e7d9ad428cc2376"

  strings:
    $s1 = "on f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"" ascii
    $s2 = "),(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"SEo\";})(),(function f000(" ascii
    $s3 = "rn \"NBs\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(" ascii
    $s4 = "on f000(){return \"Ot\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"" ascii
    $s5 = " f000(){return \"Yv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"DI" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}