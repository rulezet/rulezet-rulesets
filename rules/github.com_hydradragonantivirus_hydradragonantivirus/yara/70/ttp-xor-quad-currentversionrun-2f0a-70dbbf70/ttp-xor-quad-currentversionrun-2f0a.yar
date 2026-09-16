rule TTP_XOR_QUAD_CurrentVersionRun_2f0a {
  strings:
    $key_2f0a = { 7c 65 [2] 58 6b [2] 73 47 [2] 5d 65 [2] 49 7e [2] 46 64 [2] 58 79 [2] 5a 78 [2] 41 7e [2] 5d 79 [2] 41 56 }

  condition:
    any of them
}