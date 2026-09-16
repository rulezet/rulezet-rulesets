rule TTP_XOR_QUAD_CurrentVersionRun_6f7c {
  strings:
    $key_6f7c = { 3c 13 [2] 18 1d [2] 33 31 [2] 1d 13 [2] 09 08 [2] 06 12 [2] 18 0f [2] 1a 0e [2] 01 08 [2] 1d 0f [2] 01 20 }

  condition:
    any of them
}