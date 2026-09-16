rule TTP_XOR_QUAD_CurrentVersionRun_7e1c {
  strings:
    $key_7e1c = { 2d 73 [2] 09 7d [2] 22 51 [2] 0c 73 [2] 18 68 [2] 17 72 [2] 09 6f [2] 0b 6e [2] 10 68 [2] 0c 6f [2] 10 40 }

  condition:
    any of them
}