rule TTP_XOR_QUAD_CurrentVersionRun_ef09 {
  strings:
    $key_ef09 = { bc 66 [2] 98 68 [2] b3 44 [2] 9d 66 [2] 89 7d [2] 86 67 [2] 98 7a [2] 9a 7b [2] 81 7d [2] 9d 7a [2] 81 55 }

  condition:
    any of them
}