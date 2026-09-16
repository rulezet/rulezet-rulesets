rule TTP_XOR_QUAD_CurrentVersionRun_2d0d {
  strings:
    $key_2d0d = { 7e 62 [2] 5a 6c [2] 71 40 [2] 5f 62 [2] 4b 79 [2] 44 63 [2] 5a 7e [2] 58 7f [2] 43 79 [2] 5f 7e [2] 43 51 }

  condition:
    any of them
}