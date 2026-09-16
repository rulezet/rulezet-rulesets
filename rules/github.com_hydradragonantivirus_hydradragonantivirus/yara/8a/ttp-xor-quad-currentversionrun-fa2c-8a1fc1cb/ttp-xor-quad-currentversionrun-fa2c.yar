rule TTP_XOR_QUAD_CurrentVersionRun_fa2c {
  strings:
    $key_fa2c = { a9 43 [2] 8d 4d [2] a6 61 [2] 88 43 [2] 9c 58 [2] 93 42 [2] 8d 5f [2] 8f 5e [2] 94 58 [2] 88 5f [2] 94 70 }

  condition:
    any of them
}