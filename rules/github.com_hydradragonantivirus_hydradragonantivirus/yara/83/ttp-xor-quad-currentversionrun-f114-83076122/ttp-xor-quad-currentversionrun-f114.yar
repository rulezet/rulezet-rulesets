rule TTP_XOR_QUAD_CurrentVersionRun_f114 {
  strings:
    $key_f114 = { a2 7b [2] 86 75 [2] ad 59 [2] 83 7b [2] 97 60 [2] 98 7a [2] 86 67 [2] 84 66 [2] 9f 60 [2] 83 67 [2] 9f 48 }

  condition:
    any of them
}