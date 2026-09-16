rule TTP_XOR_QUAD_CurrentVersionRun_4c2a {
  strings:
    $key_4c2a = { 1f 45 [2] 3b 4b [2] 10 67 [2] 3e 45 [2] 2a 5e [2] 25 44 [2] 3b 59 [2] 39 58 [2] 22 5e [2] 3e 59 [2] 22 76 }

  condition:
    any of them
}