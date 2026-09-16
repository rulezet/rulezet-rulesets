rule TTP_XOR_QUAD_CurrentVersionRun_3576 {
  strings:
    $key_3576 = { 66 19 [2] 42 17 [2] 69 3b [2] 47 19 [2] 53 02 [2] 5c 18 [2] 42 05 [2] 40 04 [2] 5b 02 [2] 47 05 [2] 5b 2a }

  condition:
    any of them
}