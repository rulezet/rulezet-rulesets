rule TTP_XOR_QUAD_CurrentVersionRun_2fec {
  strings:
    $key_2fec = { 7c 83 [2] 58 8d [2] 73 a1 [2] 5d 83 [2] 49 98 [2] 46 82 [2] 58 9f [2] 5a 9e [2] 41 98 [2] 5d 9f [2] 41 b0 }

  condition:
    any of them
}