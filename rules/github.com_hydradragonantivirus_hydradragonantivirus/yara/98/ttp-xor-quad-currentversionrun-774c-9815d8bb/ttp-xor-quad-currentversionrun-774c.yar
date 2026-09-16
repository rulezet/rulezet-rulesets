rule TTP_XOR_QUAD_CurrentVersionRun_774c {
  strings:
    $key_774c = { 24 23 [2] 00 2d [2] 2b 01 [2] 05 23 [2] 11 38 [2] 1e 22 [2] 00 3f [2] 02 3e [2] 19 38 [2] 05 3f [2] 19 10 }

  condition:
    any of them
}