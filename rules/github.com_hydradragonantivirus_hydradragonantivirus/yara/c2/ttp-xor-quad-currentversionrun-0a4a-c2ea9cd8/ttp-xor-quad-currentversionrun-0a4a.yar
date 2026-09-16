rule TTP_XOR_QUAD_CurrentVersionRun_0a4a {
  strings:
    $key_0a4a = { 59 25 [2] 7d 2b [2] 56 07 [2] 78 25 [2] 6c 3e [2] 63 24 [2] 7d 39 [2] 7f 38 [2] 64 3e [2] 78 39 [2] 64 16 }

  condition:
    any of them
}