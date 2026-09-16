rule TTP_XOR_QUAD_CurrentVersionRun_3719 {
  strings:
    $key_3719 = { 64 76 [2] 40 78 [2] 6b 54 [2] 45 76 [2] 51 6d [2] 5e 77 [2] 40 6a [2] 42 6b [2] 59 6d [2] 45 6a [2] 59 45 }

  condition:
    any of them
}