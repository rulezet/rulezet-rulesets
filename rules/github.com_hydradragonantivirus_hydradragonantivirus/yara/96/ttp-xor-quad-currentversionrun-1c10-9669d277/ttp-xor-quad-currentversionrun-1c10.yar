rule TTP_XOR_QUAD_CurrentVersionRun_1c10 {
  strings:
    $key_1c10 = { 4f 7f [2] 6b 71 [2] 40 5d [2] 6e 7f [2] 7a 64 [2] 75 7e [2] 6b 63 [2] 69 62 [2] 72 64 [2] 6e 63 [2] 72 4c }

  condition:
    any of them
}