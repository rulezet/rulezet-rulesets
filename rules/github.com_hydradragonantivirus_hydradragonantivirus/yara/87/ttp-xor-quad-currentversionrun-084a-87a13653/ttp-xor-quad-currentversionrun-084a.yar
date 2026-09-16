rule TTP_XOR_QUAD_CurrentVersionRun_084a {
  strings:
    $key_084a = { 5b 25 [2] 7f 2b [2] 54 07 [2] 7a 25 [2] 6e 3e [2] 61 24 [2] 7f 39 [2] 7d 38 [2] 66 3e [2] 7a 39 [2] 66 16 }

  condition:
    any of them
}