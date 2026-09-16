rule TTP_XOR_QUAD_CurrentVersionRun_7862 {
  strings:
    $key_7862 = { 2b 0d [2] 0f 03 [2] 24 2f [2] 0a 0d [2] 1e 16 [2] 11 0c [2] 0f 11 [2] 0d 10 [2] 16 16 [2] 0a 11 [2] 16 3e }

  condition:
    any of them
}