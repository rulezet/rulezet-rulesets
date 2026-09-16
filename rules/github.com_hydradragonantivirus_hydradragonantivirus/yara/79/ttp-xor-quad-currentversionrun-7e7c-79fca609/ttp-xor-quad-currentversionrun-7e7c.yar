rule TTP_XOR_QUAD_CurrentVersionRun_7e7c {
  strings:
    $key_7e7c = { 2d 13 [2] 09 1d [2] 22 31 [2] 0c 13 [2] 18 08 [2] 17 12 [2] 09 0f [2] 0b 0e [2] 10 08 [2] 0c 0f [2] 10 20 }

  condition:
    any of them
}