rule _20160921_052a35c432a4a9609498b7ee9b4395a2_20160921_3a10cf806284_4215 {
  meta:
    description = "datamaliciousorder - from files 20160921_052a35c432a4a9609498b7ee9b4395a2.js, 20160921_3a10cf80628434d9e46f20272ebff11d.js, 20160921_a5297a3430b731f07a8b2bd532530907.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "209fd59dbb6143d03e0b3619c6d5cc33114cb8e3b4f252eb6d9da074e7636495"
    hash2       = "c217c4eb7bba8a6770bdd6609635a67fc8772b37668310875b4f4f1ff0b472c2"
    hash3       = "3cc34a5e206b8e31e54d9f96ede8214dea00b391969498f92170a493ebd7aa45"

  strings:
    $s1 = "uck(){return \"Vf\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"YQt" ascii
    $s2 = "eturn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jh\";})()," ascii
    $s3 = "n fuck(){return \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return " ascii
    $s4 = "urn \"Ai\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Oh\";})(),(fu" ascii
    $s5 = ")(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}