rule TTP_XOR_QUAD_CurrentVersionRun_774f {
  strings:
    $key_774f = { 24 20 [2] 00 2e [2] 2b 02 [2] 05 20 [2] 11 3b [2] 1e 21 [2] 00 3c [2] 02 3d [2] 19 3b [2] 05 3c [2] 19 13 }

  condition:
    any of them
}