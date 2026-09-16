rule TTP_XOR_QUAD_CurrentVersionRun_0872 {
  strings:
    $key_0872 = { 5b 1d [2] 7f 13 [2] 54 3f [2] 7a 1d [2] 6e 06 [2] 61 1c [2] 7f 01 [2] 7d 00 [2] 66 06 [2] 7a 01 [2] 66 2e }

  condition:
    any of them
}