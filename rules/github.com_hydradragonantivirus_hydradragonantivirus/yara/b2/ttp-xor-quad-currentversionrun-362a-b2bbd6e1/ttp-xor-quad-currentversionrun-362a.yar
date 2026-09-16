rule TTP_XOR_QUAD_CurrentVersionRun_362a {
  strings:
    $key_362a = { 65 45 [2] 41 4b [2] 6a 67 [2] 44 45 [2] 50 5e [2] 5f 44 [2] 41 59 [2] 43 58 [2] 58 5e [2] 44 59 [2] 58 76 }

  condition:
    any of them
}