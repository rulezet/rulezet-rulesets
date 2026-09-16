rule TTP_XOR_QUAD_CurrentVersionRun_a7b9 {
  strings:
    $key_a7b9 = { f4 d6 [2] d0 d8 [2] fb f4 [2] d5 d6 [2] c1 cd [2] ce d7 [2] d0 ca [2] d2 cb [2] c9 cd [2] d5 ca [2] c9 e5 }

  condition:
    any of them
}