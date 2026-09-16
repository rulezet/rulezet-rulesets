rule TTP_XOR_QUAD_CurrentVersionRun_f1e7 {
  strings:
    $key_f1e7 = { a2 88 [2] 86 86 [2] ad aa [2] 83 88 [2] 97 93 [2] 98 89 [2] 86 94 [2] 84 95 [2] 9f 93 [2] 83 94 [2] 9f bb }

  condition:
    any of them
}