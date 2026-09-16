rule TTP_XOR_QUAD_CurrentVersionRun_042a {
  strings:
    $key_042a = { 57 45 [2] 73 4b [2] 58 67 [2] 76 45 [2] 62 5e [2] 6d 44 [2] 73 59 [2] 71 58 [2] 6a 5e [2] 76 59 [2] 6a 76 }

  condition:
    any of them
}