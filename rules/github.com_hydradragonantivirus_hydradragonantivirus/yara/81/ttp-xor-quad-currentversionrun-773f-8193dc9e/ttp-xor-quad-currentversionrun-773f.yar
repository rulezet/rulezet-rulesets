rule TTP_XOR_QUAD_CurrentVersionRun_773f {
  strings:
    $key_773f = { 24 50 [2] 00 5e [2] 2b 72 [2] 05 50 [2] 11 4b [2] 1e 51 [2] 00 4c [2] 02 4d [2] 19 4b [2] 05 4c [2] 19 63 }

  condition:
    any of them
}