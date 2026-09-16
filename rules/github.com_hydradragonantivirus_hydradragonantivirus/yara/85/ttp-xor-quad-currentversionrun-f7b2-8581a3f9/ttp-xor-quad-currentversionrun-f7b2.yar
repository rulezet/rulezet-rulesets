rule TTP_XOR_QUAD_CurrentVersionRun_f7b2 {
  strings:
    $key_f7b2 = { a4 dd [2] 80 d3 [2] ab ff [2] 85 dd [2] 91 c6 [2] 9e dc [2] 80 c1 [2] 82 c0 [2] 99 c6 [2] 85 c1 [2] 99 ee }

  condition:
    any of them
}