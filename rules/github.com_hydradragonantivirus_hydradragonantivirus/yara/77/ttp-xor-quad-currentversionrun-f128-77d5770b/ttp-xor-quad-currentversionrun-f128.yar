rule TTP_XOR_QUAD_CurrentVersionRun_f128 {
  strings:
    $key_f128 = { a2 47 [2] 86 49 [2] ad 65 [2] 83 47 [2] 97 5c [2] 98 46 [2] 86 5b [2] 84 5a [2] 9f 5c [2] 83 5b [2] 9f 74 }

  condition:
    any of them
}