rule TTP_XOR_QUAD_CurrentVersionRun_e6a0 {
  strings:
    $key_e6a0 = { b5 cf [2] 91 c1 [2] ba ed [2] 94 cf [2] 80 d4 [2] 8f ce [2] 91 d3 [2] 93 d2 [2] 88 d4 [2] 94 d3 [2] 88 fc }

  condition:
    any of them
}