rule TTP_XOR_QUAD_CurrentVersionRun_e54b {
  strings:
    $key_e54b = { b6 24 [2] 92 2a [2] b9 06 [2] 97 24 [2] 83 3f [2] 8c 25 [2] 92 38 [2] 90 39 [2] 8b 3f [2] 97 38 [2] 8b 17 }

  condition:
    any of them
}