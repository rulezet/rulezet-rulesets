rule TTP_XOR_QUAD_CurrentVersionRun_560d {
  strings:
    $key_560d = { 05 62 [2] 21 6c [2] 0a 40 [2] 24 62 [2] 30 79 [2] 3f 63 [2] 21 7e [2] 23 7f [2] 38 79 [2] 24 7e [2] 38 51 }

  condition:
    any of them
}