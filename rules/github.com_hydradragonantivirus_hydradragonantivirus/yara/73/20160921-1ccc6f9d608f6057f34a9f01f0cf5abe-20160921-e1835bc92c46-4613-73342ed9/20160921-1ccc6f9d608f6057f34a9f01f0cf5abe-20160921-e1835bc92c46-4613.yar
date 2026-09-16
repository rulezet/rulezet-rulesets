rule _20160921_1ccc6f9d608f6057f34a9f01f0cf5abe_20160921_e1835bc92c46_4613 {
  meta:
    description = "datamaliciousorder - from files 20160921_1ccc6f9d608f6057f34a9f01f0cf5abe.js, 20160921_e1835bc92c4604db194bc49df621cade.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "226d26c073abdcaab4155bb0b8d789289cf0a453f58c9f6383385cc78660a27e"
    hash2       = "ca98fbe0aef0208d6ee3df93c692fee8802fb2206893dc56e723bc4af714c0fd"

  strings:
    $s1 = "urn \"OUx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})()," ascii
    $s2 = "{return \"Sv\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})" ascii
    $s3 = "\"Vj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(funct" ascii
    $s4 = ",(function f000(){return \"OMd\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"XTn\";})(),(function f000(){" ascii
    $s5 = "n \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"XTn\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}