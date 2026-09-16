rule TTP_XOR_QUAD_CurrentVersionRun_7a76 {
  strings:
    $key_7a76 = { 29 19 [2] 0d 17 [2] 26 3b [2] 08 19 [2] 1c 02 [2] 13 18 [2] 0d 05 [2] 0f 04 [2] 14 02 [2] 08 05 [2] 14 2a }

  condition:
    any of them
}