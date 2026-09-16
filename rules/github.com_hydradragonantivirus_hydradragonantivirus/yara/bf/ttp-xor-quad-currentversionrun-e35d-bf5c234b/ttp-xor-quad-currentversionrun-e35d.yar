rule TTP_XOR_QUAD_CurrentVersionRun_e35d {
  strings:
    $key_e35d = { b0 32 [2] 94 3c [2] bf 10 [2] 91 32 [2] 85 29 [2] 8a 33 [2] 94 2e [2] 96 2f [2] 8d 29 [2] 91 2e [2] 8d 01 }

  condition:
    any of them
}