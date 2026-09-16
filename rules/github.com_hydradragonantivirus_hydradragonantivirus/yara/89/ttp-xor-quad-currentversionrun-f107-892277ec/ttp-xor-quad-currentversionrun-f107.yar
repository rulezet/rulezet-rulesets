rule TTP_XOR_QUAD_CurrentVersionRun_f107 {
  strings:
    $key_f107 = { a2 68 [2] 86 66 [2] ad 4a [2] 83 68 [2] 97 73 [2] 98 69 [2] 86 74 [2] 84 75 [2] 9f 73 [2] 83 74 [2] 9f 5b }

  condition:
    any of them
}