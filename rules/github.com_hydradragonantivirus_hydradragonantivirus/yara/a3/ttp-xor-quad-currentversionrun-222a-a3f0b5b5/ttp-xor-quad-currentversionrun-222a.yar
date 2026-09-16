rule TTP_XOR_QUAD_CurrentVersionRun_222a {
  strings:
    $key_222a = { 71 45 [2] 55 4b [2] 7e 67 [2] 50 45 [2] 44 5e [2] 4b 44 [2] 55 59 [2] 57 58 [2] 4c 5e [2] 50 59 [2] 4c 76 }

  condition:
    any of them
}