rule TTP_XOR_QUAD_CurrentVersionRun_0d56 {
  strings:
    $key_0d56 = { 5e 39 [2] 7a 37 [2] 51 1b [2] 7f 39 [2] 6b 22 [2] 64 38 [2] 7a 25 [2] 78 24 [2] 63 22 [2] 7f 25 [2] 63 0a }

  condition:
    any of them
}