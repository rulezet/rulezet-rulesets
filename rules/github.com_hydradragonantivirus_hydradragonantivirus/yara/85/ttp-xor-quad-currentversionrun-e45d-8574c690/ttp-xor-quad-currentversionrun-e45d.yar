rule TTP_XOR_QUAD_CurrentVersionRun_e45d {
  strings:
    $key_e45d = { b7 32 [2] 93 3c [2] b8 10 [2] 96 32 [2] 82 29 [2] 8d 33 [2] 93 2e [2] 91 2f [2] 8a 29 [2] 96 2e [2] 8a 01 }

  condition:
    any of them
}