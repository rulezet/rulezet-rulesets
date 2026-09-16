rule TTP_XOR_QUAD_CurrentVersionRun_2e0a {
  strings:
    $key_2e0a = { 7d 65 [2] 59 6b [2] 72 47 [2] 5c 65 [2] 48 7e [2] 47 64 [2] 59 79 [2] 5b 78 [2] 40 7e [2] 5c 79 [2] 40 56 }

  condition:
    any of them
}