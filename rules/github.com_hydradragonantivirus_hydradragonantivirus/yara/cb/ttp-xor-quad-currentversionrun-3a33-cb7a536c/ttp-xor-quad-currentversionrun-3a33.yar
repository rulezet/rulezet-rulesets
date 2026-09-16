rule TTP_XOR_QUAD_CurrentVersionRun_3a33 {
  strings:
    $key_3a33 = { 69 5c [2] 4d 52 [2] 66 7e [2] 48 5c [2] 5c 47 [2] 53 5d [2] 4d 40 [2] 4f 41 [2] 54 47 [2] 48 40 [2] 54 6f }

  condition:
    any of them
}