rule TTP_XOR_QUAD_CurrentVersionRun_782a {
  strings:
    $key_782a = { 2b 45 [2] 0f 4b [2] 24 67 [2] 0a 45 [2] 1e 5e [2] 11 44 [2] 0f 59 [2] 0d 58 [2] 16 5e [2] 0a 59 [2] 16 76 }

  condition:
    any of them
}