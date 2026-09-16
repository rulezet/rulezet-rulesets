rule TTP_XOR_QUAD_CurrentVersionRun_beaf {
  strings:
    $key_beaf = { ed c0 [2] c9 ce [2] e2 e2 [2] cc c0 [2] d8 db [2] d7 c1 [2] c9 dc [2] cb dd [2] d0 db [2] cc dc [2] d0 f3 }

  condition:
    any of them
}