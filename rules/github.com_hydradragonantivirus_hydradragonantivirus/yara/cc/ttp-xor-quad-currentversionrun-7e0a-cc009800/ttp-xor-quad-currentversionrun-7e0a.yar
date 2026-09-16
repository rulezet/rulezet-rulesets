rule TTP_XOR_QUAD_CurrentVersionRun_7e0a {
  strings:
    $key_7e0a = { 2d 65 [2] 09 6b [2] 22 47 [2] 0c 65 [2] 18 7e [2] 17 64 [2] 09 79 [2] 0b 78 [2] 10 7e [2] 0c 79 [2] 10 56 }

  condition:
    any of them
}