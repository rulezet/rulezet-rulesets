rule TTP_XOR_QUAD_CurrentVersionRun_0eb2 {
  strings:
    $key_0eb2 = { 5d dd [2] 79 d3 [2] 52 ff [2] 7c dd [2] 68 c6 [2] 67 dc [2] 79 c1 [2] 7b c0 [2] 60 c6 [2] 7c c1 [2] 60 ee }

  condition:
    any of them
}