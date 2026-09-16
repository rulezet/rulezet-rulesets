rule TTP_XOR_QUAD_CurrentVersionRun_4b2a {
  strings:
    $key_4b2a = { 18 45 [2] 3c 4b [2] 17 67 [2] 39 45 [2] 2d 5e [2] 22 44 [2] 3c 59 [2] 3e 58 [2] 25 5e [2] 39 59 [2] 25 76 }

  condition:
    any of them
}