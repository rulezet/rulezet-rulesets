rule TTP_XOR_QUAD_CurrentVersionRun_ec9d {
  strings:
    $key_ec9d = { bf f2 [2] 9b fc [2] b0 d0 [2] 9e f2 [2] 8a e9 [2] 85 f3 [2] 9b ee [2] 99 ef [2] 82 e9 [2] 9e ee [2] 82 c1 }

  condition:
    any of them
}