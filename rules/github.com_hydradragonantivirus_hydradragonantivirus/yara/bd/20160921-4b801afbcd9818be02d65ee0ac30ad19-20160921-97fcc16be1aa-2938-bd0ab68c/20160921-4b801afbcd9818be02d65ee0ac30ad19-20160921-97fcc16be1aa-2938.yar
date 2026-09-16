rule _20160921_4b801afbcd9818be02d65ee0ac30ad19_20160921_97fcc16be1aa_2938 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b801afbcd9818be02d65ee0ac30ad19.js, 20160921_97fcc16be1aae58b311e71df667be641.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f85dba2504097034fa23d87391ecdaf7fe5f29824616a8d91d353284964bfac1"
    hash2       = "2459214bba37a40478bc984d75c7b1ababcbf0d17eeabe32578555058bdac21f"

  strings:
    $s1 = " f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"S" ascii
    $s2 = "(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"MMz\";" ascii
    $s3 = "n \"Nv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s4 = "Kw\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function" ascii
    $s5 = "{return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(" ascii
    $s6 = "),(function f000(){return \"ZFe\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Uo\";})(),(function f000()" ascii
    $s7 = " f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"U" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}