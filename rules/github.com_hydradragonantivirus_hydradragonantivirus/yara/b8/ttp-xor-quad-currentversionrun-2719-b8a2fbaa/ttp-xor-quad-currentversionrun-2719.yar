rule TTP_XOR_QUAD_CurrentVersionRun_2719 {
  strings:
    $key_2719 = { 74 76 [2] 50 78 [2] 7b 54 [2] 55 76 [2] 41 6d [2] 4e 77 [2] 50 6a [2] 52 6b [2] 49 6d [2] 55 6a [2] 49 45 }

  condition:
    any of them
}