rule TTP_XOR_QUAD_CurrentVersionRun_1b0d {
  strings:
    $key_1b0d = { 48 62 [2] 6c 6c [2] 47 40 [2] 69 62 [2] 7d 79 [2] 72 63 [2] 6c 7e [2] 6e 7f [2] 75 79 [2] 69 7e [2] 75 51 }

  condition:
    any of them
}