rule TTP_XOR_QUAD_CurrentVersionRun_2f6c {
  strings:
    $key_2f6c = { 7c 03 [2] 58 0d [2] 73 21 [2] 5d 03 [2] 49 18 [2] 46 02 [2] 58 1f [2] 5a 1e [2] 41 18 [2] 5d 1f [2] 41 30 }

  condition:
    any of them
}