rule TTP_XOR_QUAD_CurrentVersionRun_ef67 {
  strings:
    $key_ef67 = { bc 08 [2] 98 06 [2] b3 2a [2] 9d 08 [2] 89 13 [2] 86 09 [2] 98 14 [2] 9a 15 [2] 81 13 [2] 9d 14 [2] 81 3b }

  condition:
    any of them
}