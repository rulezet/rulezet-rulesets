rule TTP_XOR_QUAD_CurrentVersionRun_ef45 {
  strings:
    $key_ef45 = { bc 2a [2] 98 24 [2] b3 08 [2] 9d 2a [2] 89 31 [2] 86 2b [2] 98 36 [2] 9a 37 [2] 81 31 [2] 9d 36 [2] 81 19 }

  condition:
    any of them
}