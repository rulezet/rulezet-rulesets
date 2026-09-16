rule TTP_XOR_QUAD_CurrentVersionRun_4eec {
  strings:
    $key_4eec = { 1d 83 [2] 39 8d [2] 12 a1 [2] 3c 83 [2] 28 98 [2] 27 82 [2] 39 9f [2] 3b 9e [2] 20 98 [2] 3c 9f [2] 20 b0 }

  condition:
    any of them
}