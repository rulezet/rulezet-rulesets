rule TTP_XOR_QUAD_CurrentVersionRun_2eb2 {
  strings:
    $key_2eb2 = { 7d dd [2] 59 d3 [2] 72 ff [2] 5c dd [2] 48 c6 [2] 47 dc [2] 59 c1 [2] 5b c0 [2] 40 c6 [2] 5c c1 [2] 40 ee }

  condition:
    any of them
}