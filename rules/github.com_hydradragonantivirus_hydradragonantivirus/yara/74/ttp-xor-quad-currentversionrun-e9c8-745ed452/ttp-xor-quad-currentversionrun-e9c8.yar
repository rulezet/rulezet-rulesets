rule TTP_XOR_QUAD_CurrentVersionRun_e9c8 {
  strings:
    $key_e9c8 = { ba a7 [2] 9e a9 [2] b5 85 [2] 9b a7 [2] 8f bc [2] 80 a6 [2] 9e bb [2] 9c ba [2] 87 bc [2] 9b bb [2] 87 94 }

  condition:
    any of them
}