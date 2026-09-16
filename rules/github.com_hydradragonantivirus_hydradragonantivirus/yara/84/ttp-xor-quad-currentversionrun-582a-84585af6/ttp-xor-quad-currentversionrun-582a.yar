rule TTP_XOR_QUAD_CurrentVersionRun_582a {
  strings:
    $key_582a = { 0b 45 [2] 2f 4b [2] 04 67 [2] 2a 45 [2] 3e 5e [2] 31 44 [2] 2f 59 [2] 2d 58 [2] 36 5e [2] 2a 59 [2] 36 76 }

  condition:
    any of them
}