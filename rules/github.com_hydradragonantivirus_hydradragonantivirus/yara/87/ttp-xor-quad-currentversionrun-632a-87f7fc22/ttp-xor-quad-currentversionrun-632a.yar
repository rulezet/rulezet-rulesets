rule TTP_XOR_QUAD_CurrentVersionRun_632a {
  strings:
    $key_632a = { 30 45 [2] 14 4b [2] 3f 67 [2] 11 45 [2] 05 5e [2] 0a 44 [2] 14 59 [2] 16 58 [2] 0d 5e [2] 11 59 [2] 0d 76 }

  condition:
    any of them
}