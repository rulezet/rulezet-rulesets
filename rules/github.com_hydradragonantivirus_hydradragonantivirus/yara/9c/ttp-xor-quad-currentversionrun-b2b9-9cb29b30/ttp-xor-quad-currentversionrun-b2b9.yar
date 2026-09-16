rule TTP_XOR_QUAD_CurrentVersionRun_b2b9 {
  strings:
    $key_b2b9 = { e1 d6 [2] c5 d8 [2] ee f4 [2] c0 d6 [2] d4 cd [2] db d7 [2] c5 ca [2] c7 cb [2] dc cd [2] c0 ca [2] dc e5 }

  condition:
    any of them
}