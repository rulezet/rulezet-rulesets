rule _20160921_87f13d652177c2ccba1196dd341efb6d_20160921_b86272ed73ce_2526 {
  meta:
    description = "datamaliciousorder - from files 20160921_87f13d652177c2ccba1196dd341efb6d.js, 20160921_b86272ed73cef9077c204056df823014.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52cce778f06a6477b6f4a6a9f48328a81d874164235533c2925fdd358b6279c3"
    hash2       = "c639defcc03ef60ba09f66ea7a3067f4493b67650049d4d5576fb24d05a2ec25"

  strings:
    $s1 = "tion f000(){return \"OUx\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Yz\";})(),(function f000(){return" ascii
    $s2 = "eturn \"Mc\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})()," ascii
    $s3 = "\"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(funct" ascii
    $s4 = "on f000(){return \"BQb\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"" ascii
    $s5 = ",(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){r" ascii
    $s6 = "n f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"" ascii
    $s7 = "(){return \"Tb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})" ascii
    $s8 = "function f000(){return \"QDg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"DIa\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}