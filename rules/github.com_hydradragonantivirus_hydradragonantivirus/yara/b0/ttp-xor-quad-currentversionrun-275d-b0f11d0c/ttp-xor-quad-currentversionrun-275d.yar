rule TTP_XOR_QUAD_CurrentVersionRun_275d {
  strings:
    $key_275d = { 74 32 [2] 50 3c [2] 7b 10 [2] 55 32 [2] 41 29 [2] 4e 33 [2] 50 2e [2] 52 2f [2] 49 29 [2] 55 2e [2] 49 01 }

  condition:
    any of them
}