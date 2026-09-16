rule TTP_XOR_QUAD_CurrentVersionRun_0a5a {
  strings:
    $key_0a5a = { 59 35 [2] 7d 3b [2] 56 17 [2] 78 35 [2] 6c 2e [2] 63 34 [2] 7d 29 [2] 7f 28 [2] 64 2e [2] 78 29 [2] 64 06 }

  condition:
    any of them
}