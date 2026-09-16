rule TTP_XOR_QUAD_CurrentVersionRun_634a {
  strings:
    $key_634a = { 30 25 [2] 14 2b [2] 3f 07 [2] 11 25 [2] 05 3e [2] 0a 24 [2] 14 39 [2] 16 38 [2] 0d 3e [2] 11 39 [2] 0d 16 }

  condition:
    any of them
}