rule TTP_XOR_QUAD_CurrentVersionRun_6533 {
  strings:
    $key_6533 = { 36 5c [2] 12 52 [2] 39 7e [2] 17 5c [2] 03 47 [2] 0c 5d [2] 12 40 [2] 10 41 [2] 0b 47 [2] 17 40 [2] 0b 6f }

  condition:
    any of them
}