rule TTP_XOR_QUAD_CurrentVersionRun_6f6a {
  strings:
    $key_6f6a = { 3c 05 [2] 18 0b [2] 33 27 [2] 1d 05 [2] 09 1e [2] 06 04 [2] 18 19 [2] 1a 18 [2] 01 1e [2] 1d 19 [2] 01 36 }

  condition:
    any of them
}