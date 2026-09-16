rule TTP_XOR_QUAD_CurrentVersionRun_375a {
  strings:
    $key_375a = { 64 35 [2] 40 3b [2] 6b 17 [2] 45 35 [2] 51 2e [2] 5e 34 [2] 40 29 [2] 42 28 [2] 59 2e [2] 45 29 [2] 59 06 }

  condition:
    any of them
}