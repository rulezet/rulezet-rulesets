rule TTP_XOR_QUAD_CurrentVersionRun_4e0d {
  strings:
    $key_4e0d = { 1d 62 [2] 39 6c [2] 12 40 [2] 3c 62 [2] 28 79 [2] 27 63 [2] 39 7e [2] 3b 7f [2] 20 79 [2] 3c 7e [2] 20 51 }

  condition:
    any of them
}