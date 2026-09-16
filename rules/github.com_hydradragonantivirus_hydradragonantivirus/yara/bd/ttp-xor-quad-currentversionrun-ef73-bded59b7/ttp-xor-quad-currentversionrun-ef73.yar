rule TTP_XOR_QUAD_CurrentVersionRun_ef73 {
  strings:
    $key_ef73 = { bc 1c [2] 98 12 [2] b3 3e [2] 9d 1c [2] 89 07 [2] 86 1d [2] 98 00 [2] 9a 01 [2] 81 07 [2] 9d 00 [2] 81 2f }

  condition:
    any of them
}