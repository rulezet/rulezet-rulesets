rule TTP_XOR_QUAD_CurrentVersionRun_375d {
  strings:
    $key_375d = { 64 32 [2] 40 3c [2] 6b 10 [2] 45 32 [2] 51 29 [2] 5e 33 [2] 40 2e [2] 42 2f [2] 59 29 [2] 45 2e [2] 59 01 }

  condition:
    any of them
}