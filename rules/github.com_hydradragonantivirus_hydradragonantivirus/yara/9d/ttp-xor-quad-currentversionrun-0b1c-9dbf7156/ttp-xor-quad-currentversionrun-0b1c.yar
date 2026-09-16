rule TTP_XOR_QUAD_CurrentVersionRun_0b1c {
  strings:
    $key_0b1c = { 58 73 [2] 7c 7d [2] 57 51 [2] 79 73 [2] 6d 68 [2] 62 72 [2] 7c 6f [2] 7e 6e [2] 65 68 [2] 79 6f [2] 65 40 }

  condition:
    any of them
}