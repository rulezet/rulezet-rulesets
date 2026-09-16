rule TTP_XOR_QUAD_CurrentVersionRun_f138 {
  strings:
    $key_f138 = { a2 57 [2] 86 59 [2] ad 75 [2] 83 57 [2] 97 4c [2] 98 56 [2] 86 4b [2] 84 4a [2] 9f 4c [2] 83 4b [2] 9f 64 }

  condition:
    any of them
}