rule TTP_XOR_QUAD_CurrentVersionRun_6205 {
  strings:
    $key_6205 = { 31 6a [2] 15 64 [2] 3e 48 [2] 10 6a [2] 04 71 [2] 0b 6b [2] 15 76 [2] 17 77 [2] 0c 71 [2] 10 76 [2] 0c 59 }

  condition:
    any of them
}