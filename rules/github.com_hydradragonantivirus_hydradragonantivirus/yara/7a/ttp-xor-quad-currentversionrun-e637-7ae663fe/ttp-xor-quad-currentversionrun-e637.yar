rule TTP_XOR_QUAD_CurrentVersionRun_e637 {
  strings:
    $key_e637 = { b5 58 [2] 91 56 [2] ba 7a [2] 94 58 [2] 80 43 [2] 8f 59 [2] 91 44 [2] 93 45 [2] 88 43 [2] 94 44 [2] 88 6b }

  condition:
    any of them
}