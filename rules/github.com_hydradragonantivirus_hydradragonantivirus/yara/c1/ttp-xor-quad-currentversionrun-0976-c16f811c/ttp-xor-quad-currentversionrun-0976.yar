rule TTP_XOR_QUAD_CurrentVersionRun_0976 {
  strings:
    $key_0976 = { 5a 19 [2] 7e 17 [2] 55 3b [2] 7b 19 [2] 6f 02 [2] 60 18 [2] 7e 05 [2] 7c 04 [2] 67 02 [2] 7b 05 [2] 67 2a }

  condition:
    any of them
}