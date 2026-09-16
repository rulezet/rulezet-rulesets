rule _20160921_28d059ae521dbabe2afdc3bfd464938c_20160921_85f6e34eb7e2_4767 {
  meta:
    description = "datamaliciousorder - from files 20160921_28d059ae521dbabe2afdc3bfd464938c.js, 20160921_85f6e34eb7e2f53408ead6aab6d7f923.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e141f467019579b96a9cc109c7a3e7efb3b51b1378b450a816089a6ae7d406f7"
    hash2       = "5005d4ac4c04b94b5c8e15a81b5b50ecf9189f0e4afa203ae5195bec5a82b02f"

  strings:
    $s1 = "{return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"UEg\";})(" ascii
    $s2 = "n \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Iq\";})(),(func" ascii
    $s3 = "Db\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"KDh\";})(),(functi" ascii
    $s4 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f00" ascii
    $s5 = "(){return \"EZu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}