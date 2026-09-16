rule TTP_XOR_QUAD_CurrentVersionRun_1a33 {
  strings:
    $key_1a33 = { 49 5c [2] 6d 52 [2] 46 7e [2] 68 5c [2] 7c 47 [2] 73 5d [2] 6d 40 [2] 6f 41 [2] 74 47 [2] 68 40 [2] 74 6f }

  condition:
    any of them
}