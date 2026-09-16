rule TTP_XOR_QUAD_CurrentVersionRun_771f {
  strings:
    $key_771f = { 24 70 [2] 00 7e [2] 2b 52 [2] 05 70 [2] 11 6b [2] 1e 71 [2] 00 6c [2] 02 6d [2] 19 6b [2] 05 6c [2] 19 43 }

  condition:
    any of them
}