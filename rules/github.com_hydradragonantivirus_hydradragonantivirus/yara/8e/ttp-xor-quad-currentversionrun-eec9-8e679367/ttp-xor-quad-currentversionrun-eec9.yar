rule TTP_XOR_QUAD_CurrentVersionRun_eec9 {
  strings:
    $key_eec9 = { bd a6 [2] 99 a8 [2] b2 84 [2] 9c a6 [2] 88 bd [2] 87 a7 [2] 99 ba [2] 9b bb [2] 80 bd [2] 9c ba [2] 80 95 }

  condition:
    any of them
}