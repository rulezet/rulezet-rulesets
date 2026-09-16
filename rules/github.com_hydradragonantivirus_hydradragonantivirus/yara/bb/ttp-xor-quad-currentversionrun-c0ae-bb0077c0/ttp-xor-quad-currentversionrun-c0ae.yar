rule TTP_XOR_QUAD_CurrentVersionRun_c0ae {
  strings:
    $key_c0ae = { 93 c1 [2] b7 cf [2] 9c e3 [2] b2 c1 [2] a6 da [2] a9 c0 [2] b7 dd [2] b5 dc [2] ae da [2] b2 dd [2] ae f2 }

  condition:
    any of them
}