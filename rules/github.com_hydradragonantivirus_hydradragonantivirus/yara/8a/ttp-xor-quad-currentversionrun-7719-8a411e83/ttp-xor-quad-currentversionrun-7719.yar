rule TTP_XOR_QUAD_CurrentVersionRun_7719 {
  strings:
    $key_7719 = { 24 76 [2] 00 78 [2] 2b 54 [2] 05 76 [2] 11 6d [2] 1e 77 [2] 00 6a [2] 02 6b [2] 19 6d [2] 05 6a [2] 19 45 }

  condition:
    any of them
}