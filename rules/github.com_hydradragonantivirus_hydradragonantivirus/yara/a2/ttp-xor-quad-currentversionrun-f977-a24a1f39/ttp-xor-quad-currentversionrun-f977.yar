rule TTP_XOR_QUAD_CurrentVersionRun_f977 {
  strings:
    $key_f977 = { aa 18 [2] 8e 16 [2] a5 3a [2] 8b 18 [2] 9f 03 [2] 90 19 [2] 8e 04 [2] 8c 05 [2] 97 03 [2] 8b 04 [2] 97 2b }

  condition:
    any of them
}