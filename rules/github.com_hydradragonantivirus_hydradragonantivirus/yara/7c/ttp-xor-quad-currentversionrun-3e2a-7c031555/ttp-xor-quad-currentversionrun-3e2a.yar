rule TTP_XOR_QUAD_CurrentVersionRun_3e2a {
  strings:
    $key_3e2a = { 6d 45 [2] 49 4b [2] 62 67 [2] 4c 45 [2] 58 5e [2] 57 44 [2] 49 59 [2] 4b 58 [2] 50 5e [2] 4c 59 [2] 50 76 }

  condition:
    any of them
}