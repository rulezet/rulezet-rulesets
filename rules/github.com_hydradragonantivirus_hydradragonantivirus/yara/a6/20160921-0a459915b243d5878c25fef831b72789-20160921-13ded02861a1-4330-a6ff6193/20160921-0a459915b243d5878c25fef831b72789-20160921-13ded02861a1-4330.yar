rule _20160921_0a459915b243d5878c25fef831b72789_20160921_13ded02861a1_4330 {
  meta:
    description = "datamaliciousorder - from files 20160921_0a459915b243d5878c25fef831b72789.js, 20160921_13ded02861a1e8b64e01061b37c5b3db.js, 20160921_b4c84c92954782bcf19013150a359ec6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f8d1944044e8a67a527f50e4aeb45e9358929b0d0f7aaf1730d2782f07a09de"
    hash2       = "42e98219bdeb7e238d75b203593219e729c68b82ade5cdcb35dd8982bca8e7b8"
    hash3       = "deac288c0b80bcd19eff4e9a4bb55e7bdc0f08b0110094a0693c671b47cda285"

  strings:
    $s1 = "z\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s2 = " \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(functi" ascii
    $s3 = "function f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){ret" ascii
    $s4 = "{return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(" ascii
    $s5 = "on f000(){return \"XTn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}