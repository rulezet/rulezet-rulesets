rule TTP_XOR_QUAD_CurrentVersionRun_2d1c {
  strings:
    $key_2d1c = { 7e 73 [2] 5a 7d [2] 71 51 [2] 5f 73 [2] 4b 68 [2] 44 72 [2] 5a 6f [2] 58 6e [2] 43 68 [2] 5f 6f [2] 43 40 }

  condition:
    any of them
}