rule TTP_XOR_QUAD_CurrentVersionRun_6df8 {
  strings:
    $key_6df8 = { 3e 97 [2] 1a 99 [2] 31 b5 [2] 1f 97 [2] 0b 8c [2] 04 96 [2] 1a 8b [2] 18 8a [2] 03 8c [2] 1f 8b [2] 03 a4 }

  condition:
    any of them
}