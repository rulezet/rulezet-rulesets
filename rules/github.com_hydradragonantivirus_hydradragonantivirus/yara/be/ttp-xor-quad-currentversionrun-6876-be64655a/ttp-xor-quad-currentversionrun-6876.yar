rule TTP_XOR_QUAD_CurrentVersionRun_6876 {
  strings:
    $key_6876 = { 3b 19 [2] 1f 17 [2] 34 3b [2] 1a 19 [2] 0e 02 [2] 01 18 [2] 1f 05 [2] 1d 04 [2] 06 02 [2] 1a 05 [2] 06 2a }

  condition:
    any of them
}