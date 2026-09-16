rule TTP_XOR_QUAD_CurrentVersionRun_0b0a {
  strings:
    $key_0b0a = { 58 65 [2] 7c 6b [2] 57 47 [2] 79 65 [2] 6d 7e [2] 62 64 [2] 7c 79 [2] 7e 78 [2] 65 7e [2] 79 79 [2] 65 56 }

  condition:
    any of them
}