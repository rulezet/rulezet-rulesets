rule TTP_XOR_QUAD_CurrentVersionRun_65b2 {
  strings:
    $key_65b2 = { 36 dd [2] 12 d3 [2] 39 ff [2] 17 dd [2] 03 c6 [2] 0c dc [2] 12 c1 [2] 10 c0 [2] 0b c6 [2] 17 c1 [2] 0b ee }

  condition:
    any of them
}