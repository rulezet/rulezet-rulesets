rule TTP_XOR_QUAD_CurrentVersionRun_7a33 {
  strings:
    $key_7a33 = { 29 5c [2] 0d 52 [2] 26 7e [2] 08 5c [2] 1c 47 [2] 13 5d [2] 0d 40 [2] 0f 41 [2] 14 47 [2] 08 40 [2] 14 6f }

  condition:
    any of them
}