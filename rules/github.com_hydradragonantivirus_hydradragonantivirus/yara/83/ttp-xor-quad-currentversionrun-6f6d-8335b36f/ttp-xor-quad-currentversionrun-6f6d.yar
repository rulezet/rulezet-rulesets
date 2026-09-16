rule TTP_XOR_QUAD_CurrentVersionRun_6f6d {
  strings:
    $key_6f6d = { 3c 02 [2] 18 0c [2] 33 20 [2] 1d 02 [2] 09 19 [2] 06 03 [2] 18 1e [2] 1a 1f [2] 01 19 [2] 1d 1e [2] 01 31 }

  condition:
    any of them
}