rule TTP_XOR_QUAD_CurrentVersionRun_5533 {
  strings:
    $key_5533 = { 06 5c [2] 22 52 [2] 09 7e [2] 27 5c [2] 33 47 [2] 3c 5d [2] 22 40 [2] 20 41 [2] 3b 47 [2] 27 40 [2] 3b 6f }

  condition:
    any of them
}