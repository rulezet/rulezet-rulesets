rule TTP_XOR_QUAD_CurrentVersionRun_f16b {
  strings:
    $key_f16b = { a2 04 [2] 86 0a [2] ad 26 [2] 83 04 [2] 97 1f [2] 98 05 [2] 86 18 [2] 84 19 [2] 9f 1f [2] 83 18 [2] 9f 37 }

  condition:
    any of them
}