rule TTP_XOR_QUAD_CurrentVersionRun_780a {
  strings:
    $key_780a = { 2b 65 [2] 0f 6b [2] 24 47 [2] 0a 65 [2] 1e 7e [2] 11 64 [2] 0f 79 [2] 0d 78 [2] 16 7e [2] 0a 79 [2] 16 56 }

  condition:
    any of them
}