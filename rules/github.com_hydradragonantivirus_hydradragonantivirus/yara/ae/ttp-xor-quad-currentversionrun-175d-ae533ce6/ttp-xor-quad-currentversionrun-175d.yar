rule TTP_XOR_QUAD_CurrentVersionRun_175d {
  strings:
    $key_175d = { 44 32 [2] 60 3c [2] 4b 10 [2] 65 32 [2] 71 29 [2] 7e 33 [2] 60 2e [2] 62 2f [2] 79 29 [2] 65 2e [2] 79 01 }

  condition:
    any of them
}