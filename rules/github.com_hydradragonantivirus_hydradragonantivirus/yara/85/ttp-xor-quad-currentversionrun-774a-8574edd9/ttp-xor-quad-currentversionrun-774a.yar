rule TTP_XOR_QUAD_CurrentVersionRun_774a {
  strings:
    $key_774a = { 24 25 [2] 00 2b [2] 2b 07 [2] 05 25 [2] 11 3e [2] 1e 24 [2] 00 39 [2] 02 38 [2] 19 3e [2] 05 39 [2] 19 16 }

  condition:
    any of them
}