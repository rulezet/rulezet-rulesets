rule _20160921_85f6e34eb7e2f53408ead6aab6d7f923_20160921_b32c8921e339_3069 {
  meta:
    description = "datamaliciousorder - from files 20160921_85f6e34eb7e2f53408ead6aab6d7f923.js, 20160921_b32c8921e3390cb8f9450436f4e43cfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5005d4ac4c04b94b5c8e15a81b5b50ecf9189f0e4afa203ae5195bec5a82b02f"
    hash2       = "5ab35ff2eba15a460823fc709e29f7c1041f054096a3690e92c926943d39d6a8"

  strings:
    $s1 = "Gn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Iq\";})(),(functio" ascii
    $s2 = "return \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Uo\";})()" ascii
    $s3 = "f000(){return \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Sj" ascii
    $s4 = "nction f000(){return \"EZu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){ret" ascii
    $s5 = "ction f000(){return \"SGs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s6 = "function f000(){return \"Sj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){retu" ascii
    $s7 = "){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mc\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}