rule TTP_XOR_QUAD_CurrentVersionRun_1758 {
  strings:
    $key_1758 = { 44 37 [2] 60 39 [2] 4b 15 [2] 65 37 [2] 71 2c [2] 7e 36 [2] 60 2b [2] 62 2a [2] 79 2c [2] 65 2b [2] 79 04 }

  condition:
    any of them
}