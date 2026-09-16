rule TTP_XOR_QUAD_CurrentVersionRun_7c0d {
  strings:
    $key_7c0d = { 2f 62 [2] 0b 6c [2] 20 40 [2] 0e 62 [2] 1a 79 [2] 15 63 [2] 0b 7e [2] 09 7f [2] 12 79 [2] 0e 7e [2] 12 51 }

  condition:
    any of them
}