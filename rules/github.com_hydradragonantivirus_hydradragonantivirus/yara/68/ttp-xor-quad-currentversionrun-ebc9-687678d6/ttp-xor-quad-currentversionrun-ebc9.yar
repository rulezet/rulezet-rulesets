rule TTP_XOR_QUAD_CurrentVersionRun_ebc9 {
  strings:
    $key_ebc9 = { b8 a6 [2] 9c a8 [2] b7 84 [2] 99 a6 [2] 8d bd [2] 82 a7 [2] 9c ba [2] 9e bb [2] 85 bd [2] 99 ba [2] 85 95 }

  condition:
    any of them
}