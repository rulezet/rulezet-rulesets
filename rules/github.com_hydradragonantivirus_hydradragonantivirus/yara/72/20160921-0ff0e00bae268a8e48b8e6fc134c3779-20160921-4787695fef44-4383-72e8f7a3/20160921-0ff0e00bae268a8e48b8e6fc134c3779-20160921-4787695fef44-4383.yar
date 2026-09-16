rule _20160921_0ff0e00bae268a8e48b8e6fc134c3779_20160921_4787695fef44_4383 {
  meta:
    description = "datamaliciousorder - from files 20160921_0ff0e00bae268a8e48b8e6fc134c3779.js, 20160921_4787695fef4453a16be881bbe0f96c1a.js, 20160921_ded524cdc972424d0fa8254648795d71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f9f30b45066ff23899a854b2ef766240b2becea05223ad11c6bf5cde97c3048"
    hash2       = "6a11e3d64ee2711e84433d2b8035ce0dafbcffa760c2026e3cfe9ba310008f90"
    hash3       = "09c4ea683259322d1696083646a9b96190b4796e8b3fdf91ba2bf4f6296afaa9"

  strings:
    $s1 = "g\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function " ascii
    $s2 = "on f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return " ascii
    $s3 = "return \"Qz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})()" ascii
    $s4 = "(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(" ascii
    $s5 = "rn \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}