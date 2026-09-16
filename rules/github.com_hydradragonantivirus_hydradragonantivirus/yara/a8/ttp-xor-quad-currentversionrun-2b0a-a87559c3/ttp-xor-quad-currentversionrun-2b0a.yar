rule TTP_XOR_QUAD_CurrentVersionRun_2b0a {
  strings:
    $key_2b0a = { 78 65 [2] 5c 6b [2] 77 47 [2] 59 65 [2] 4d 7e [2] 42 64 [2] 5c 79 [2] 5e 78 [2] 45 7e [2] 59 79 [2] 45 56 }

  condition:
    any of them
}