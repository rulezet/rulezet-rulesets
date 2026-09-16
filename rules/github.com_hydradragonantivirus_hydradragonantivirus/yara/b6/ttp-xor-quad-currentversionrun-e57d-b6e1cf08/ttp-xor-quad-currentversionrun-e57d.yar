rule TTP_XOR_QUAD_CurrentVersionRun_e57d {
  strings:
    $key_e57d = { b6 12 [2] 92 1c [2] b9 30 [2] 97 12 [2] 83 09 [2] 8c 13 [2] 92 0e [2] 90 0f [2] 8b 09 [2] 97 0e [2] 8b 21 }

  condition:
    any of them
}