rule TTP_XOR_QUAD_CurrentVersionRun_6d0a {
  strings:
    $key_6d0a = { 3e 65 [2] 1a 6b [2] 31 47 [2] 1f 65 [2] 0b 7e [2] 04 64 [2] 1a 79 [2] 18 78 [2] 03 7e [2] 1f 79 [2] 03 56 }

  condition:
    any of them
}