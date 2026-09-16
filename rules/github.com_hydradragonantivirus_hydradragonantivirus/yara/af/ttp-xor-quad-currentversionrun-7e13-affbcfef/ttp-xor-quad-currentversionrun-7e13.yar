rule TTP_XOR_QUAD_CurrentVersionRun_7e13 {
  strings:
    $key_7e13 = { 2d 7c [2] 09 72 [2] 22 5e [2] 0c 7c [2] 18 67 [2] 17 7d [2] 09 60 [2] 0b 61 [2] 10 67 [2] 0c 60 [2] 10 4f }

  condition:
    any of them
}