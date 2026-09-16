rule TTP_XOR_QUAD_CurrentVersionRun_a4b9 {
  strings:
    $key_a4b9 = { f7 d6 [2] d3 d8 [2] f8 f4 [2] d6 d6 [2] c2 cd [2] cd d7 [2] d3 ca [2] d1 cb [2] ca cd [2] d6 ca [2] ca e5 }

  condition:
    any of them
}