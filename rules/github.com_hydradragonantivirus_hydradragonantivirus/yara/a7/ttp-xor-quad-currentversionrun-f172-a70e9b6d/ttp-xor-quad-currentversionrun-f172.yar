rule TTP_XOR_QUAD_CurrentVersionRun_f172 {
  strings:
    $key_f172 = { a2 1d [2] 86 13 [2] ad 3f [2] 83 1d [2] 97 06 [2] 98 1c [2] 86 01 [2] 84 00 [2] 9f 06 [2] 83 01 [2] 9f 2e }

  condition:
    any of them
}