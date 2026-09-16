rule TTP_XOR_QUAD_CurrentVersionRun_ef63 {
  strings:
    $key_ef63 = { bc 0c [2] 98 02 [2] b3 2e [2] 9d 0c [2] 89 17 [2] 86 0d [2] 98 10 [2] 9a 11 [2] 81 17 [2] 9d 10 [2] 81 3f }

  condition:
    any of them
}