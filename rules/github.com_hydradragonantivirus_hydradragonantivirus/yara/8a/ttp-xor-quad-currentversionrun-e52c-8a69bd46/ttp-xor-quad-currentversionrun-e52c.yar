rule TTP_XOR_QUAD_CurrentVersionRun_e52c {
  strings:
    $key_e52c = { b6 43 [2] 92 4d [2] b9 61 [2] 97 43 [2] 83 58 [2] 8c 42 [2] 92 5f [2] 90 5e [2] 8b 58 [2] 97 5f [2] 8b 70 }

  condition:
    any of them
}