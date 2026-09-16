rule TTP_XOR_QUAD_CurrentVersionRun_ef14 {
  strings:
    $key_ef14 = { bc 7b [2] 98 75 [2] b3 59 [2] 9d 7b [2] 89 60 [2] 86 7a [2] 98 67 [2] 9a 66 [2] 81 60 [2] 9d 67 [2] 81 48 }

  condition:
    any of them
}