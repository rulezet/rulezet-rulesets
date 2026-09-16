rule TTP_XOR_QUAD_CurrentVersionRun_5f0a {
  strings:
    $key_5f0a = { 0c 65 [2] 28 6b [2] 03 47 [2] 2d 65 [2] 39 7e [2] 36 64 [2] 28 79 [2] 2a 78 [2] 31 7e [2] 2d 79 [2] 31 56 }

  condition:
    any of them
}