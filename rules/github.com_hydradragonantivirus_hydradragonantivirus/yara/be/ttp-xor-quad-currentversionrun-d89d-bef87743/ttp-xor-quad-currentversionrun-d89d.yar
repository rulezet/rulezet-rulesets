rule TTP_XOR_QUAD_CurrentVersionRun_d89d {
  strings:
    $key_d89d = { 8b f2 [2] af fc [2] 84 d0 [2] aa f2 [2] be e9 [2] b1 f3 [2] af ee [2] ad ef [2] b6 e9 [2] aa ee [2] b6 c1 }

  condition:
    any of them
}