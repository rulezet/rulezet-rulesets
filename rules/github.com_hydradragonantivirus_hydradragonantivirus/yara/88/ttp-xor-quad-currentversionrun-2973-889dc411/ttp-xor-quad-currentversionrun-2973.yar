rule TTP_XOR_QUAD_CurrentVersionRun_2973 {
  strings:
    $key_2973 = { 7a 1c [2] 5e 12 [2] 75 3e [2] 5b 1c [2] 4f 07 [2] 40 1d [2] 5e 00 [2] 5c 01 [2] 47 07 [2] 5b 00 [2] 47 2f }

  condition:
    any of them
}