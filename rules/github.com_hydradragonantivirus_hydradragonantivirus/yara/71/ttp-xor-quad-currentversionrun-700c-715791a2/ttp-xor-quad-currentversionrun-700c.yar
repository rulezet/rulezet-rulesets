rule TTP_XOR_QUAD_CurrentVersionRun_700c {
  strings:
    $key_700c = { 23 63 [2] 07 6d [2] 2c 41 [2] 02 63 [2] 16 78 [2] 19 62 [2] 07 7f [2] 05 7e [2] 1e 78 [2] 02 7f [2] 1e 50 }

  condition:
    any of them
}