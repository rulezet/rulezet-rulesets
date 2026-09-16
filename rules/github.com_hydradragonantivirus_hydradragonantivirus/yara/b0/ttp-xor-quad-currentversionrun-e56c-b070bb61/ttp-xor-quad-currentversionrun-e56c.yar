rule TTP_XOR_QUAD_CurrentVersionRun_e56c {
  strings:
    $key_e56c = { b6 03 [2] 92 0d [2] b9 21 [2] 97 03 [2] 83 18 [2] 8c 02 [2] 92 1f [2] 90 1e [2] 8b 18 [2] 97 1f [2] 8b 30 }

  condition:
    any of them
}