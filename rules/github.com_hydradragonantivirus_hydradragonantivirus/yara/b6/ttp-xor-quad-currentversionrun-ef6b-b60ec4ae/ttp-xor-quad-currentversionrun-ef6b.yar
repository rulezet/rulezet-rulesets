rule TTP_XOR_QUAD_CurrentVersionRun_ef6b {
  strings:
    $key_ef6b = { bc 04 [2] 98 0a [2] b3 26 [2] 9d 04 [2] 89 1f [2] 86 05 [2] 98 18 [2] 9a 19 [2] 81 1f [2] 9d 18 [2] 81 37 }

  condition:
    any of them
}