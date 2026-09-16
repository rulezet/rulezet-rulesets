rule TTP_XOR_QUAD_CurrentVersionRun_350a {
  strings:
    $key_350a = { 66 65 [2] 42 6b [2] 69 47 [2] 47 65 [2] 53 7e [2] 5c 64 [2] 42 79 [2] 40 78 [2] 5b 7e [2] 47 79 [2] 5b 56 }

  condition:
    any of them
}