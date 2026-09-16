rule TTP_XOR_QUAD_CurrentVersionRun_f4b2 {
  strings:
    $key_f4b2 = { a7 dd [2] 83 d3 [2] a8 ff [2] 86 dd [2] 92 c6 [2] 9d dc [2] 83 c1 [2] 81 c0 [2] 9a c6 [2] 86 c1 [2] 9a ee }

  condition:
    any of them
}