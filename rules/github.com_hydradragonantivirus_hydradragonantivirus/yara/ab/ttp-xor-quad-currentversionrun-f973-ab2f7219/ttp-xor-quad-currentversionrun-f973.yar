rule TTP_XOR_QUAD_CurrentVersionRun_f973 {
  strings:
    $key_f973 = { aa 1c [2] 8e 12 [2] a5 3e [2] 8b 1c [2] 9f 07 [2] 90 1d [2] 8e 00 [2] 8c 01 [2] 97 07 [2] 8b 00 [2] 97 2f }

  condition:
    any of them
}