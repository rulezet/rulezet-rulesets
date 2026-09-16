rule TTP_XOR_QUAD_CurrentVersionRun_642a {
  strings:
    $key_642a = { 37 45 [2] 13 4b [2] 38 67 [2] 16 45 [2] 02 5e [2] 0d 44 [2] 13 59 [2] 11 58 [2] 0a 5e [2] 16 59 [2] 0a 76 }

  condition:
    any of them
}