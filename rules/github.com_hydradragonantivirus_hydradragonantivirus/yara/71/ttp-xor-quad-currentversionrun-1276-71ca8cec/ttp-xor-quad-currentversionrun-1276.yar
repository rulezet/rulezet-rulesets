rule TTP_XOR_QUAD_CurrentVersionRun_1276 {
  strings:
    $key_1276 = { 41 19 [2] 65 17 [2] 4e 3b [2] 60 19 [2] 74 02 [2] 7b 18 [2] 65 05 [2] 67 04 [2] 7c 02 [2] 60 05 [2] 7c 2a }

  condition:
    any of them
}