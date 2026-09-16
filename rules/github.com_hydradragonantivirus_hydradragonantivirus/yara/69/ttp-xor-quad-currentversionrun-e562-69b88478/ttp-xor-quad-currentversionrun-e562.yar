rule TTP_XOR_QUAD_CurrentVersionRun_e562 {
  strings:
    $key_e562 = { b6 0d [2] 92 03 [2] b9 2f [2] 97 0d [2] 83 16 [2] 8c 0c [2] 92 11 [2] 90 10 [2] 8b 16 [2] 97 11 [2] 8b 3e }

  condition:
    any of them
}