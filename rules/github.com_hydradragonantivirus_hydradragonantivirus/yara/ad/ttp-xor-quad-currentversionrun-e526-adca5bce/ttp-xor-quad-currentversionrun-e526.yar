rule TTP_XOR_QUAD_CurrentVersionRun_e526 {
  strings:
    $key_e526 = { b6 49 [2] 92 47 [2] b9 6b [2] 97 49 [2] 83 52 [2] 8c 48 [2] 92 55 [2] 90 54 [2] 8b 52 [2] 97 55 [2] 8b 7a }

  condition:
    any of them
}