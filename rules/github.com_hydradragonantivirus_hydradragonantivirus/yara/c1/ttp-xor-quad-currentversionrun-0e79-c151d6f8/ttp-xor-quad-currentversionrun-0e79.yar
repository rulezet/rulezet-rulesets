rule TTP_XOR_QUAD_CurrentVersionRun_0e79 {
  strings:
    $key_0e79 = { 5d 16 [2] 79 18 [2] 52 34 [2] 7c 16 [2] 68 0d [2] 67 17 [2] 79 0a [2] 7b 0b [2] 60 0d [2] 7c 0a [2] 60 25 }

  condition:
    any of them
}