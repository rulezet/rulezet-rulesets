rule TTP_XOR_QUAD_CurrentVersionRun_7876 {
  strings:
    $key_7876 = { 2b 19 [2] 0f 17 [2] 24 3b [2] 0a 19 [2] 1e 02 [2] 11 18 [2] 0f 05 [2] 0d 04 [2] 16 02 [2] 0a 05 [2] 16 2a }

  condition:
    any of them
}