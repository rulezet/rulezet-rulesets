rule TTP_XOR_QUAD_CurrentVersionRun_785d {
  strings:
    $key_785d = { 2b 32 [2] 0f 3c [2] 24 10 [2] 0a 32 [2] 1e 29 [2] 11 33 [2] 0f 2e [2] 0d 2f [2] 16 29 [2] 0a 2e [2] 16 01 }

  condition:
    any of them
}