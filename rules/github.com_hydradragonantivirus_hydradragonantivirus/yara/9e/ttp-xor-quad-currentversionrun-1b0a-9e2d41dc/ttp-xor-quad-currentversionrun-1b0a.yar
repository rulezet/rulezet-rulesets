rule TTP_XOR_QUAD_CurrentVersionRun_1b0a {
  strings:
    $key_1b0a = { 48 65 [2] 6c 6b [2] 47 47 [2] 69 65 [2] 7d 7e [2] 72 64 [2] 6c 79 [2] 6e 78 [2] 75 7e [2] 69 79 [2] 75 56 }

  condition:
    any of them
}