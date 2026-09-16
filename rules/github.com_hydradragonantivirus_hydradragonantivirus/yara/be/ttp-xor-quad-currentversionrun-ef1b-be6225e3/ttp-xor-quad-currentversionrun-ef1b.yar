rule TTP_XOR_QUAD_CurrentVersionRun_ef1b {
  strings:
    $key_ef1b = { bc 74 [2] 98 7a [2] b3 56 [2] 9d 74 [2] 89 6f [2] 86 75 [2] 98 68 [2] 9a 69 [2] 81 6f [2] 9d 68 [2] 81 47 }

  condition:
    any of them
}