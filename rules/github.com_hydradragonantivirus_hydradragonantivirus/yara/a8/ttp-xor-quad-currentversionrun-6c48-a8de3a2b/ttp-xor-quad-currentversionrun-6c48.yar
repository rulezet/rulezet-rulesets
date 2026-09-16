rule TTP_XOR_QUAD_CurrentVersionRun_6c48 {
  strings:
    $key_6c48 = { 3f 27 [2] 1b 29 [2] 30 05 [2] 1e 27 [2] 0a 3c [2] 05 26 [2] 1b 3b [2] 19 3a [2] 02 3c [2] 1e 3b [2] 02 14 }

  condition:
    any of them
}