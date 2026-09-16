rule TTP_XOR_QUAD_CurrentVersionRun_692c {
  strings:
    $key_692c = { 3a 43 [2] 1e 4d [2] 35 61 [2] 1b 43 [2] 0f 58 [2] 00 42 [2] 1e 5f [2] 1c 5e [2] 07 58 [2] 1b 5f [2] 07 70 }

  condition:
    any of them
}