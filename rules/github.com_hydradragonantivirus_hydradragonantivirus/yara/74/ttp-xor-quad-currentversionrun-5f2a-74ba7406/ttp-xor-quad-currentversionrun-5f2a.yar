rule TTP_XOR_QUAD_CurrentVersionRun_5f2a {
  strings:
    $key_5f2a = { 0c 45 [2] 28 4b [2] 03 67 [2] 2d 45 [2] 39 5e [2] 36 44 [2] 28 59 [2] 2a 58 [2] 31 5e [2] 2d 59 [2] 31 76 }

  condition:
    any of them
}