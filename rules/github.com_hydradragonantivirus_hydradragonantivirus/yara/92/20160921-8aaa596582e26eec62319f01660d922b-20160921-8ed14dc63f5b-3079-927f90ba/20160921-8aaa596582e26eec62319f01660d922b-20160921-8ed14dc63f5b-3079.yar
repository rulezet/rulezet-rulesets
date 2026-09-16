rule _20160921_8aaa596582e26eec62319f01660d922b_20160921_8ed14dc63f5b_3079 {
  meta:
    description = "datamaliciousorder - from files 20160921_8aaa596582e26eec62319f01660d922b.js, 20160921_8ed14dc63f5bac37baa70510a94f2915.js, 20160921_b2867778b87ab68774c77840f21eaed0.js, 20160922_2c550b6efe6ec163893e1c555d256b4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "345c67f8d573844507dfad7f05cf340f1a2bb19331e3e0d242c508445594aac6"
    hash2       = "e01d4cea60f1c16b2fc3a28a98b5ad4d421b0c4e8e5f757805e98a1436a9fadd"
    hash3       = "ae46b7285b241d53af42d1248b27d7d1186f12901d6fc0284d48665a3b217777"
    hash4       = "deabc297df80ed9899178f4a02c9538b2fe3ee2038528e07da89655f0d68b1a1"

  strings:
    $s1 = "return \"Qa\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(" ascii
    $s2 = "Gn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s3 = "on f000(){return \"HJm\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s4 = "0(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MJq" ascii
    $s5 = "),(function f000(){return \"HJm\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"XTn\";})(),(function f000()" ascii
    $s6 = "00(){return \"WIj\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Wb" ascii
    $s7 = "SEo\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}