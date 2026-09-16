rule TTP_XOR_QUAD_CurrentVersionRun_ee9d {
  strings:
    $key_ee9d = { bd f2 [2] 99 fc [2] b2 d0 [2] 9c f2 [2] 88 e9 [2] 87 f3 [2] 99 ee [2] 9b ef [2] 80 e9 [2] 9c ee [2] 80 c1 }

  condition:
    any of them
}