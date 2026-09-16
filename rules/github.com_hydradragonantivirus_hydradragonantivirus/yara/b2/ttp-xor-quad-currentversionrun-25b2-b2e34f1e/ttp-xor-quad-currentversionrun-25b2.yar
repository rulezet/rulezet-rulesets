rule TTP_XOR_QUAD_CurrentVersionRun_25b2 {
  strings:
    $key_25b2 = { 76 dd [2] 52 d3 [2] 79 ff [2] 57 dd [2] 43 c6 [2] 4c dc [2] 52 c1 [2] 50 c0 [2] 4b c6 [2] 57 c1 [2] 4b ee }

  condition:
    any of them
}