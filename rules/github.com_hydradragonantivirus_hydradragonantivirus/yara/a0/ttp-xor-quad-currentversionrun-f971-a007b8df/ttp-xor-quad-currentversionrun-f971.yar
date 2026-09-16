rule TTP_XOR_QUAD_CurrentVersionRun_f971 {
  strings:
    $key_f971 = { aa 1e [2] 8e 10 [2] a5 3c [2] 8b 1e [2] 9f 05 [2] 90 1f [2] 8e 02 [2] 8c 03 [2] 97 05 [2] 8b 02 [2] 97 2d }

  condition:
    any of them
}