rule TTP_XOR_QUAD_CurrentVersionRun_310a {
  strings:
    $key_310a = { 62 65 [2] 46 6b [2] 6d 47 [2] 43 65 [2] 57 7e [2] 58 64 [2] 46 79 [2] 44 78 [2] 5f 7e [2] 43 79 [2] 5f 56 }

  condition:
    any of them
}