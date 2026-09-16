rule TTP_XOR_QUAD_CurrentVersionRun_fbc9 {
  strings:
    $key_fbc9 = { a8 a6 [2] 8c a8 [2] a7 84 [2] 89 a6 [2] 9d bd [2] 92 a7 [2] 8c ba [2] 8e bb [2] 95 bd [2] 89 ba [2] 95 95 }

  condition:
    any of them
}