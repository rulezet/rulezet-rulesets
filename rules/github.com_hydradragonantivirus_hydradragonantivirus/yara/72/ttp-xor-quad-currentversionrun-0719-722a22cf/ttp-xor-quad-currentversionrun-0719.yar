rule TTP_XOR_QUAD_CurrentVersionRun_0719 {
  strings:
    $key_0719 = { 54 76 [2] 70 78 [2] 5b 54 [2] 75 76 [2] 61 6d [2] 6e 77 [2] 70 6a [2] 72 6b [2] 69 6d [2] 75 6a [2] 69 45 }

  condition:
    any of them
}