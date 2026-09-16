rule TTP_XOR_QUAD_CurrentVersionRun_f956 {
  strings:
    $key_f956 = { aa 39 [2] 8e 37 [2] a5 1b [2] 8b 39 [2] 9f 22 [2] 90 38 [2] 8e 25 [2] 8c 24 [2] 97 22 [2] 8b 25 [2] 97 0a }

  condition:
    any of them
}