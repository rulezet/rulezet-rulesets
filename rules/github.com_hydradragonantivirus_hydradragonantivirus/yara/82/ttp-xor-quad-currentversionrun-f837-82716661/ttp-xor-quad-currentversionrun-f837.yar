rule TTP_XOR_QUAD_CurrentVersionRun_f837 {
  strings:
    $key_f837 = { ab 58 [2] 8f 56 [2] a4 7a [2] 8a 58 [2] 9e 43 [2] 91 59 [2] 8f 44 [2] 8d 45 [2] 96 43 [2] 8a 44 [2] 96 6b }

  condition:
    any of them
}