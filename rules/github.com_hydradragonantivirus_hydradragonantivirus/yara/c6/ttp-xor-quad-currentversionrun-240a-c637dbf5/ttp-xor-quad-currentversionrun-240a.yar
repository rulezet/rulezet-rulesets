rule TTP_XOR_QUAD_CurrentVersionRun_240a {
  strings:
    $key_240a = { 77 65 [2] 53 6b [2] 78 47 [2] 56 65 [2] 42 7e [2] 4d 64 [2] 53 79 [2] 51 78 [2] 4a 7e [2] 56 79 [2] 4a 56 }

  condition:
    any of them
}