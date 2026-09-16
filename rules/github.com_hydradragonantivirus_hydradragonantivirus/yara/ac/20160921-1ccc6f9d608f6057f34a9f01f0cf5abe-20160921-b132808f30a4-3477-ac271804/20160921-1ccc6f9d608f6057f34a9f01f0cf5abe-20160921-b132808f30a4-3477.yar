rule _20160921_1ccc6f9d608f6057f34a9f01f0cf5abe_20160921_b132808f30a4_3477 {
  meta:
    description = "datamaliciousorder - from files 20160921_1ccc6f9d608f6057f34a9f01f0cf5abe.js, 20160921_b132808f30a4f3b5c484e9734dc93fcc.js, 20160921_e1c974d7750547ace34afdda5a06de15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "226d26c073abdcaab4155bb0b8d789289cf0a453f58c9f6383385cc78660a27e"
    hash2       = "03f070dd06dae48f7c253ddc9a238e441aaac22f9de6e238ba5d3ffa0b9220b4"
    hash3       = "bed4e8c71e09f1ca8c800564bc43d4e103353ec558d1f0869c85d3e8f8c43b01"

  strings:
    $s1 = "QDg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(functio" ascii
    $s2 = "on f000(){return \"Uo\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"DIa\";})(),(function f000(){return " ascii
    $s3 = "){return \"Qz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})" ascii
    $s4 = "})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f00" ascii
    $s5 = "ction f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Do\";})(),(function f000(){retur" ascii
    $s6 = "tion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}