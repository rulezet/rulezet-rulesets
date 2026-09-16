rule TTP_XOR_QUAD_CurrentVersionRun_0e2a {
  strings:
    $key_0e2a = { 5d 45 [2] 79 4b [2] 52 67 [2] 7c 45 [2] 68 5e [2] 67 44 [2] 79 59 [2] 7b 58 [2] 60 5e [2] 7c 59 [2] 60 76 }

  condition:
    any of them
}