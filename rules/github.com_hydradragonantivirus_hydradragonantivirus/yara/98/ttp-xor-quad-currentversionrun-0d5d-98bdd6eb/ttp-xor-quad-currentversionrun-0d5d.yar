rule TTP_XOR_QUAD_CurrentVersionRun_0d5d {
  strings:
    $key_0d5d = { 5e 32 [2] 7a 3c [2] 51 10 [2] 7f 32 [2] 6b 29 [2] 64 33 [2] 7a 2e [2] 78 2f [2] 63 29 [2] 7f 2e [2] 63 01 }

  condition:
    any of them
}