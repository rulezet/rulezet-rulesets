rule TTP_XOR_QUAD_CurrentVersionRun_4539 {
  strings:
    $key_4539 = { 16 56 [2] 32 58 [2] 19 74 [2] 37 56 [2] 23 4d [2] 2c 57 [2] 32 4a [2] 30 4b [2] 2b 4d [2] 37 4a [2] 2b 65 }

  condition:
    any of them
}