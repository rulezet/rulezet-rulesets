rule TTP_XOR_QUAD_CurrentVersionRun_e437 {
  strings:
    $key_e437 = { b7 58 [2] 93 56 [2] b8 7a [2] 96 58 [2] 82 43 [2] 8d 59 [2] 93 44 [2] 91 45 [2] 8a 43 [2] 96 44 [2] 8a 6b }

  condition:
    any of them
}