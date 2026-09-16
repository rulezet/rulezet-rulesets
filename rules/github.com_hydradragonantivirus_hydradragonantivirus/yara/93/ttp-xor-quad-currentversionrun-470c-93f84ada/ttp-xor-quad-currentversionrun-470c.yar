rule TTP_XOR_QUAD_CurrentVersionRun_470c {
  strings:
    $key_470c = { 14 63 [2] 30 6d [2] 1b 41 [2] 35 63 [2] 21 78 [2] 2e 62 [2] 30 7f [2] 32 7e [2] 29 78 [2] 35 7f [2] 29 50 }

  condition:
    any of them
}