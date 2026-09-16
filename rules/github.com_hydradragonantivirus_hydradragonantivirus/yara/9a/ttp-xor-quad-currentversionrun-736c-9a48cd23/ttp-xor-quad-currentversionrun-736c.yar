rule TTP_XOR_QUAD_CurrentVersionRun_736c {
  strings:
    $key_736c = { 20 03 [2] 04 0d [2] 2f 21 [2] 01 03 [2] 15 18 [2] 1a 02 [2] 04 1f [2] 06 1e [2] 1d 18 [2] 01 1f [2] 1d 30 }

  condition:
    any of them
}