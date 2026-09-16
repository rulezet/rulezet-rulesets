rule TTP_XOR_QUAD_CurrentVersionRun_ad90 {
  strings:
    $key_ad90 = { fe ff [2] da f1 [2] f1 dd [2] df ff [2] cb e4 [2] c4 fe [2] da e3 [2] d8 e2 [2] c3 e4 [2] df e3 [2] c3 cc }

  condition:
    any of them
}