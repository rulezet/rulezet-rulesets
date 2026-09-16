rule TTP_XOR_QUAD_CurrentVersionRun_6df9 {
  strings:
    $key_6df9 = { 3e 96 [2] 1a 98 [2] 31 b4 [2] 1f 96 [2] 0b 8d [2] 04 97 [2] 1a 8a [2] 18 8b [2] 03 8d [2] 1f 8a [2] 03 a5 }

  condition:
    any of them
}