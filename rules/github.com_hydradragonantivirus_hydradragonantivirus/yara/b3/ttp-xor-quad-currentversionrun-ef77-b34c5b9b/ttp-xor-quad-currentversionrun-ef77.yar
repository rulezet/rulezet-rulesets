rule TTP_XOR_QUAD_CurrentVersionRun_ef77 {
  strings:
    $key_ef77 = { bc 18 [2] 98 16 [2] b3 3a [2] 9d 18 [2] 89 03 [2] 86 19 [2] 98 04 [2] 9a 05 [2] 81 03 [2] 9d 04 [2] 81 2b }

  condition:
    any of them
}