rule TTP_XOR_QUAD_CurrentVersionRun_385a {
  strings:
    $key_385a = { 6b 35 [2] 4f 3b [2] 64 17 [2] 4a 35 [2] 5e 2e [2] 51 34 [2] 4f 29 [2] 4d 28 [2] 56 2e [2] 4a 29 [2] 56 06 }

  condition:
    any of them
}