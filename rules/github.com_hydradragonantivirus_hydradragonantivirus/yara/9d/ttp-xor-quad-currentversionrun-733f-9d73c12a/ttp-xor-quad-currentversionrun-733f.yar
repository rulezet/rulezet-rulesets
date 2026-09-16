rule TTP_XOR_QUAD_CurrentVersionRun_733f {
  strings:
    $key_733f = { 20 50 [2] 04 5e [2] 2f 72 [2] 01 50 [2] 15 4b [2] 1a 51 [2] 04 4c [2] 06 4d [2] 1d 4b [2] 01 4c [2] 1d 63 }

  condition:
    any of them
}