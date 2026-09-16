rule TTP_XOR_QUAD_CurrentVersionRun_0b6c {
  strings:
    $key_0b6c = { 58 03 [2] 7c 0d [2] 57 21 [2] 79 03 [2] 6d 18 [2] 62 02 [2] 7c 1f [2] 7e 1e [2] 65 18 [2] 79 1f [2] 65 30 }

  condition:
    any of them
}