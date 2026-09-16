rule TTP_XOR_QUAD_CurrentVersionRun_2e5d {
  strings:
    $key_2e5d = { 7d 32 [2] 59 3c [2] 72 10 [2] 5c 32 [2] 48 29 [2] 47 33 [2] 59 2e [2] 5b 2f [2] 40 29 [2] 5c 2e [2] 40 01 }

  condition:
    any of them
}