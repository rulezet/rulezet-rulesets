rule TTP_XOR_QUAD_CurrentVersionRun_0c0a {
  strings:
    $key_0c0a = { 5f 65 [2] 7b 6b [2] 50 47 [2] 7e 65 [2] 6a 7e [2] 65 64 [2] 7b 79 [2] 79 78 [2] 62 7e [2] 7e 79 [2] 62 56 }

  condition:
    any of them
}