rule TTP_XOR_QUAD_CurrentVersionRun_e54c {
  strings:
    $key_e54c = { b6 23 [2] 92 2d [2] b9 01 [2] 97 23 [2] 83 38 [2] 8c 22 [2] 92 3f [2] 90 3e [2] 8b 38 [2] 97 3f [2] 8b 10 }

  condition:
    any of them
}