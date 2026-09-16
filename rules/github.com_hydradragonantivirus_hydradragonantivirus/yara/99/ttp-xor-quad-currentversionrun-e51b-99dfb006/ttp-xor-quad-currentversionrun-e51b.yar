rule TTP_XOR_QUAD_CurrentVersionRun_e51b {
  strings:
    $key_e51b = { b6 74 [2] 92 7a [2] b9 56 [2] 97 74 [2] 83 6f [2] 8c 75 [2] 92 68 [2] 90 69 [2] 8b 6f [2] 97 68 [2] 8b 47 }

  condition:
    any of them
}