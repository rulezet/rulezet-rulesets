rule TTP_XOR_QUAD_CurrentVersionRun_e50b {
  strings:
    $key_e50b = { b6 64 [2] 92 6a [2] b9 46 [2] 97 64 [2] 83 7f [2] 8c 65 [2] 92 78 [2] 90 79 [2] 8b 7f [2] 97 78 [2] 8b 57 }

  condition:
    any of them
}