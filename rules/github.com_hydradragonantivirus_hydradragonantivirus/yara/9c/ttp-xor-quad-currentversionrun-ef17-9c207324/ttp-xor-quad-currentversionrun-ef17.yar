rule TTP_XOR_QUAD_CurrentVersionRun_ef17 {
  strings:
    $key_ef17 = { bc 78 [2] 98 76 [2] b3 5a [2] 9d 78 [2] 89 63 [2] 86 79 [2] 98 64 [2] 9a 65 [2] 81 63 [2] 9d 64 [2] 81 4b }

  condition:
    any of them
}