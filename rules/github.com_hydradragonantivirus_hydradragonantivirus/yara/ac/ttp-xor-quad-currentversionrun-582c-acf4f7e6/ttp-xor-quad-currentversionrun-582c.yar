rule TTP_XOR_QUAD_CurrentVersionRun_582c {
  strings:
    $key_582c = { 0b 43 [2] 2f 4d [2] 04 61 [2] 2a 43 [2] 3e 58 [2] 31 42 [2] 2f 5f [2] 2d 5e [2] 36 58 [2] 2a 5f [2] 36 70 }

  condition:
    any of them
}