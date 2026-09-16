rule TTP_XOR_QUAD_CurrentVersionRun_ec9c {
  strings:
    $key_ec9c = { bf f3 [2] 9b fd [2] b0 d1 [2] 9e f3 [2] 8a e8 [2] 85 f2 [2] 9b ef [2] 99 ee [2] 82 e8 [2] 9e ef [2] 82 c0 }

  condition:
    any of them
}