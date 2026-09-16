rule TTP_XOR_QUAD_CurrentVersionRun_f961 {
  strings:
    $key_f961 = { aa 0e [2] 8e 00 [2] a5 2c [2] 8b 0e [2] 9f 15 [2] 90 0f [2] 8e 12 [2] 8c 13 [2] 97 15 [2] 8b 12 [2] 97 3d }

  condition:
    any of them
}