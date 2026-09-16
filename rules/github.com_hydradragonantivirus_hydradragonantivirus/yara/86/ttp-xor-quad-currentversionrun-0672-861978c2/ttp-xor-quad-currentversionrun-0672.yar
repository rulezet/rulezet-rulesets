rule TTP_XOR_QUAD_CurrentVersionRun_0672 {
  strings:
    $key_0672 = { 55 1d [2] 71 13 [2] 5a 3f [2] 74 1d [2] 60 06 [2] 6f 1c [2] 71 01 [2] 73 00 [2] 68 06 [2] 74 01 [2] 68 2e }

  condition:
    any of them
}