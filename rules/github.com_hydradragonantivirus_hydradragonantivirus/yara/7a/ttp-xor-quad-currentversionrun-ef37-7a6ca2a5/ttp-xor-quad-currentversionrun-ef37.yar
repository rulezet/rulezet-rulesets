rule TTP_XOR_QUAD_CurrentVersionRun_ef37 {
  strings:
    $key_ef37 = { bc 58 [2] 98 56 [2] b3 7a [2] 9d 58 [2] 89 43 [2] 86 59 [2] 98 44 [2] 9a 45 [2] 81 43 [2] 9d 44 [2] 81 6b }

  condition:
    any of them
}