rule TTP_XOR_QUAD_CurrentVersionRun_2a0a {
  strings:
    $key_2a0a = { 79 65 [2] 5d 6b [2] 76 47 [2] 58 65 [2] 4c 7e [2] 43 64 [2] 5d 79 [2] 5f 78 [2] 44 7e [2] 58 79 [2] 44 56 }

  condition:
    any of them
}