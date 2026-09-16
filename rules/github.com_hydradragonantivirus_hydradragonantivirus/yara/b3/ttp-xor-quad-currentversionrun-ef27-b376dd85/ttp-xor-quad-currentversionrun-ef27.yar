rule TTP_XOR_QUAD_CurrentVersionRun_ef27 {
  strings:
    $key_ef27 = { bc 48 [2] 98 46 [2] b3 6a [2] 9d 48 [2] 89 53 [2] 86 49 [2] 98 54 [2] 9a 55 [2] 81 53 [2] 9d 54 [2] 81 7b }

  condition:
    any of them
}