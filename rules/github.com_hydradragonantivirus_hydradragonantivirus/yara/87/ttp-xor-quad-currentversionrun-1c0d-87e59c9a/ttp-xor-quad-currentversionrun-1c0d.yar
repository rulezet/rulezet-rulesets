rule TTP_XOR_QUAD_CurrentVersionRun_1c0d {
  strings:
    $key_1c0d = { 4f 62 [2] 6b 6c [2] 40 40 [2] 6e 62 [2] 7a 79 [2] 75 63 [2] 6b 7e [2] 69 7f [2] 72 79 [2] 6e 7e [2] 72 51 }

  condition:
    any of them
}