rule TTP_XOR_QUAD_CurrentVersionRun_edb2 {
  strings:
    $key_edb2 = { be dd [2] 9a d3 [2] b1 ff [2] 9f dd [2] 8b c6 [2] 84 dc [2] 9a c1 [2] 98 c0 [2] 83 c6 [2] 9f c1 [2] 83 ee }

  condition:
    any of them
}