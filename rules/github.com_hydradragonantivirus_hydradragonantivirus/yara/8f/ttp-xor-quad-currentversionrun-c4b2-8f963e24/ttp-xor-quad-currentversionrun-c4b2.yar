rule TTP_XOR_QUAD_CurrentVersionRun_c4b2 {
  strings:
    $key_c4b2 = { 97 dd [2] b3 d3 [2] 98 ff [2] b6 dd [2] a2 c6 [2] ad dc [2] b3 c1 [2] b1 c0 [2] aa c6 [2] b6 c1 [2] aa ee }

  condition:
    any of them
}