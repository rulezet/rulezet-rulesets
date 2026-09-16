rule TTP_XOR_QUAD_CurrentVersionRun_e7f8 {
  strings:
    $key_e7f8 = { b4 97 [2] 90 99 [2] bb b5 [2] 95 97 [2] 81 8c [2] 8e 96 [2] 90 8b [2] 92 8a [2] 89 8c [2] 95 8b [2] 89 a4 }

  condition:
    any of them
}