rule TTP_XOR_QUAD_CurrentVersionRun_f5b2 {
  strings:
    $key_f5b2 = { a6 dd [2] 82 d3 [2] a9 ff [2] 87 dd [2] 93 c6 [2] 9c dc [2] 82 c1 [2] 80 c0 [2] 9b c6 [2] 87 c1 [2] 9b ee }

  condition:
    any of them
}