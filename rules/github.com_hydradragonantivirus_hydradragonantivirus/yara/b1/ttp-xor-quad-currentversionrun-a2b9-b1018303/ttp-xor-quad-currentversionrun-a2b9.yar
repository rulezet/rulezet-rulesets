rule TTP_XOR_QUAD_CurrentVersionRun_a2b9 {
  strings:
    $key_a2b9 = { f1 d6 [2] d5 d8 [2] fe f4 [2] d0 d6 [2] c4 cd [2] cb d7 [2] d5 ca [2] d7 cb [2] cc cd [2] d0 ca [2] cc e5 }

  condition:
    any of them
}