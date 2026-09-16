rule _20160921_016aab466e10a29b831eb85b27664027_20160921_b86272ed73ce_2594 {
  meta:
    description = "datamaliciousorder - from files 20160921_016aab466e10a29b831eb85b27664027.js, 20160921_b86272ed73cef9077c204056df823014.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6a541dd7e97eedc43f6bcf89f007176352c81c1d1240a76218e73cf5bb3b171"
    hash2       = "c639defcc03ef60ba09f66ea7a3067f4493b67650049d4d5576fb24d05a2ec25"

  strings:
    $s1 = "rn \"IAa\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Vu\";})(),(f" ascii
    $s2 = "000(){return \"Um\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\"" ascii
    $s3 = "n \"DIa\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(fu" ascii
    $s4 = "0(){return \"WIj\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oe\";" ascii
    $s5 = "turn \"DNa\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KDh\";})()," ascii
    $s6 = ",(function f000(){return \"KDh\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"KXg\";})(),(function f000()" ascii
    $s7 = "n f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}