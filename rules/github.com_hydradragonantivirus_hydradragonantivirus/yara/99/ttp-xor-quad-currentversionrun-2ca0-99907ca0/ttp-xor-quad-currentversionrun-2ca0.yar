rule TTP_XOR_QUAD_CurrentVersionRun_2ca0 {
  strings:
    $key_2ca0 = { 7f cf [2] 5b c1 [2] 70 ed [2] 5e cf [2] 4a d4 [2] 45 ce [2] 5b d3 [2] 59 d2 [2] 42 d4 [2] 5e d3 [2] 42 fc }

  condition:
    any of them
}