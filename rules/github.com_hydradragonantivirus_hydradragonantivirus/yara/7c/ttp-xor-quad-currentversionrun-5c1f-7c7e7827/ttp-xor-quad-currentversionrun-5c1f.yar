rule TTP_XOR_QUAD_CurrentVersionRun_5c1f {
  strings:
    $key_5c1f = { 0f 70 [2] 2b 7e [2] 00 52 [2] 2e 70 [2] 3a 6b [2] 35 71 [2] 2b 6c [2] 29 6d [2] 32 6b [2] 2e 6c [2] 32 43 }

  condition:
    any of them
}