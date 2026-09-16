rule TTP_XOR_QUAD_CurrentVersionRun_ef07 {
  strings:
    $key_ef07 = { bc 68 [2] 98 66 [2] b3 4a [2] 9d 68 [2] 89 73 [2] 86 69 [2] 98 74 [2] 9a 75 [2] 81 73 [2] 9d 74 [2] 81 5b }

  condition:
    any of them
}