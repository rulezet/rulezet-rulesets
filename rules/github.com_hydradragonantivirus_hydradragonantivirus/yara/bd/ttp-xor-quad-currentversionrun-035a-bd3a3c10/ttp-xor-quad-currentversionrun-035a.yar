rule TTP_XOR_QUAD_CurrentVersionRun_035a {
  strings:
    $key_035a = { 50 35 [2] 74 3b [2] 5f 17 [2] 71 35 [2] 65 2e [2] 6a 34 [2] 74 29 [2] 76 28 [2] 6d 2e [2] 71 29 [2] 6d 06 }

  condition:
    any of them
}