rule TTP_XOR_QUAD_CurrentVersionRun_e5b2 {
  strings:
    $key_e5b2 = { b6 dd [2] 92 d3 [2] b9 ff [2] 97 dd [2] 83 c6 [2] 8c dc [2] 92 c1 [2] 90 c0 [2] 8b c6 [2] 97 c1 [2] 8b ee }

  condition:
    any of them
}