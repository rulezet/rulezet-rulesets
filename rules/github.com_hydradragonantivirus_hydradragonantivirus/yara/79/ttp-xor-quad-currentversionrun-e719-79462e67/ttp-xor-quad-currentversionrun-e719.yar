rule TTP_XOR_QUAD_CurrentVersionRun_e719 {
  strings:
    $key_e719 = { b4 76 [2] 90 78 [2] bb 54 [2] 95 76 [2] 81 6d [2] 8e 77 [2] 90 6a [2] 92 6b [2] 89 6d [2] 95 6a [2] 89 45 }

  condition:
    any of them
}