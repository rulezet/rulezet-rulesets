rule TTP_XOR_QUAD_CurrentVersionRun_7fec {
  strings:
    $key_7fec = { 2c 83 [2] 08 8d [2] 23 a1 [2] 0d 83 [2] 19 98 [2] 16 82 [2] 08 9f [2] 0a 9e [2] 11 98 [2] 0d 9f [2] 11 b0 }

  condition:
    any of them
}