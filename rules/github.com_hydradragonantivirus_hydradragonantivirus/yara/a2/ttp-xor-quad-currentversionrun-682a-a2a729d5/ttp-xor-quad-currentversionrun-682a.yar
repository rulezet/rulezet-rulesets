rule TTP_XOR_QUAD_CurrentVersionRun_682a {
  strings:
    $key_682a = { 3b 45 [2] 1f 4b [2] 34 67 [2] 1a 45 [2] 0e 5e [2] 01 44 [2] 1f 59 [2] 1d 58 [2] 06 5e [2] 1a 59 [2] 06 76 }

  condition:
    any of them
}