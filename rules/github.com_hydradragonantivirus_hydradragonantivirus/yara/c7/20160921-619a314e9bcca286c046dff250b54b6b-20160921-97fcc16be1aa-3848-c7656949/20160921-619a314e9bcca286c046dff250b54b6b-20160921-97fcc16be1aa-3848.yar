rule _20160921_619a314e9bcca286c046dff250b54b6b_20160921_97fcc16be1aa_3848 {
  meta:
    description = "datamaliciousorder - from files 20160921_619a314e9bcca286c046dff250b54b6b.js, 20160921_97fcc16be1aae58b311e71df667be641.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f370548310908c52102d40d56781574ad404eafca7ac832d5e52d48f722bff5"
    hash2       = "2459214bba37a40478bc984d75c7b1ababcbf0d17eeabe32578555058bdac21f"

  strings:
    $s1 = "return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oh\";})()," ascii
    $s2 = "return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Iq\";})()" ascii
    $s3 = " \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(fun" ascii
    $s4 = "rn \"WIj\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(f" ascii
    $s5 = "n f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"" ascii
    $s6 = "return \"Vj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}