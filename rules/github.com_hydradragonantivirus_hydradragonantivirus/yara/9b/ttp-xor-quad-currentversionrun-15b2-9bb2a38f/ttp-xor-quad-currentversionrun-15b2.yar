rule TTP_XOR_QUAD_CurrentVersionRun_15b2 {
  strings:
    $key_15b2 = { 46 dd [2] 62 d3 [2] 49 ff [2] 67 dd [2] 73 c6 [2] 7c dc [2] 62 c1 [2] 60 c0 [2] 7b c6 [2] 67 c1 [2] 7b ee }

  condition:
    any of them
}