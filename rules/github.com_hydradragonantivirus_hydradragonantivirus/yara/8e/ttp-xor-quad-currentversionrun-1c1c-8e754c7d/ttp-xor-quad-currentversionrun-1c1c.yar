rule TTP_XOR_QUAD_CurrentVersionRun_1c1c {
  strings:
    $key_1c1c = { 4f 73 [2] 6b 7d [2] 40 51 [2] 6e 73 [2] 7a 68 [2] 75 72 [2] 6b 6f [2] 69 6e [2] 72 68 [2] 6e 6f [2] 72 40 }

  condition:
    any of them
}