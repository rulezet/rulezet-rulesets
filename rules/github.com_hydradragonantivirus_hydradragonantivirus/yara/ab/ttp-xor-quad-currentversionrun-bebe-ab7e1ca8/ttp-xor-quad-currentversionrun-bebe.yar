rule TTP_XOR_QUAD_CurrentVersionRun_bebe {
  strings:
    $key_bebe = { ed d1 [2] c9 df [2] e2 f3 [2] cc d1 [2] d8 ca [2] d7 d0 [2] c9 cd [2] cb cc [2] d0 ca [2] cc cd [2] d0 e2 }

  condition:
    any of them
}