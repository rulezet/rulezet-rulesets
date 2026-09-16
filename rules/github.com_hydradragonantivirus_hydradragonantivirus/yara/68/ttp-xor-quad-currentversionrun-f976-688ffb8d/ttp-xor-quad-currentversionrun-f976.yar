rule TTP_XOR_QUAD_CurrentVersionRun_f976 {
  strings:
    $key_f976 = { aa 19 [2] 8e 17 [2] a5 3b [2] 8b 19 [2] 9f 02 [2] 90 18 [2] 8e 05 [2] 8c 04 [2] 97 02 [2] 8b 05 [2] 97 2a }

  condition:
    any of them
}