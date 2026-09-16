rule TTP_XOR_QUAD_CurrentVersionRun_3276 {
  strings:
    $key_3276 = { 61 19 [2] 45 17 [2] 6e 3b [2] 40 19 [2] 54 02 [2] 5b 18 [2] 45 05 [2] 47 04 [2] 5c 02 [2] 40 05 [2] 5c 2a }

  condition:
    any of them
}