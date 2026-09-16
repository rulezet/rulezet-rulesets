rule TTP_XOR_QUAD_CurrentVersionRun_2f33 {
  strings:
    $key_2f33 = { 7c 5c [2] 58 52 [2] 73 7e [2] 5d 5c [2] 49 47 [2] 46 5d [2] 58 40 [2] 5a 41 [2] 41 47 [2] 5d 40 [2] 41 6f }

  condition:
    any of them
}