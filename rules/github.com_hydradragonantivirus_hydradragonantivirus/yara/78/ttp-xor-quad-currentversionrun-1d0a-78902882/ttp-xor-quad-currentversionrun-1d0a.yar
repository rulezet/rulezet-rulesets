rule TTP_XOR_QUAD_CurrentVersionRun_1d0a {
  strings:
    $key_1d0a = { 4e 65 [2] 6a 6b [2] 41 47 [2] 6f 65 [2] 7b 7e [2] 74 64 [2] 6a 79 [2] 68 78 [2] 73 7e [2] 6f 79 [2] 73 56 }

  condition:
    any of them
}