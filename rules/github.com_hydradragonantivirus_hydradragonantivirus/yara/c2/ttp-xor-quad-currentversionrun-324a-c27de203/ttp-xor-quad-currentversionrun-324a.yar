rule TTP_XOR_QUAD_CurrentVersionRun_324a {
  strings:
    $key_324a = { 61 25 [2] 45 2b [2] 6e 07 [2] 40 25 [2] 54 3e [2] 5b 24 [2] 45 39 [2] 47 38 [2] 5c 3e [2] 40 39 [2] 5c 16 }

  condition:
    any of them
}