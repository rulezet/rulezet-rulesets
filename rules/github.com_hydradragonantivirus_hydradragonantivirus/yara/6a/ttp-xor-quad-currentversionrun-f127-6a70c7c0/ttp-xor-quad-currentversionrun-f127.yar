rule TTP_XOR_QUAD_CurrentVersionRun_f127 {
  strings:
    $key_f127 = { a2 48 [2] 86 46 [2] ad 6a [2] 83 48 [2] 97 53 [2] 98 49 [2] 86 54 [2] 84 55 [2] 9f 53 [2] 83 54 [2] 9f 7b }

  condition:
    any of them
}