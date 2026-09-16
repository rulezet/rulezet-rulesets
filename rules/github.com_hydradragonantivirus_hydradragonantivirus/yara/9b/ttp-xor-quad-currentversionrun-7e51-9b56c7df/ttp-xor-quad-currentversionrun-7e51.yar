rule TTP_XOR_QUAD_CurrentVersionRun_7e51 {
  strings:
    $key_7e51 = { 2d 3e [2] 09 30 [2] 22 1c [2] 0c 3e [2] 18 25 [2] 17 3f [2] 09 22 [2] 0b 23 [2] 10 25 [2] 0c 22 [2] 10 0d }

  condition:
    any of them
}