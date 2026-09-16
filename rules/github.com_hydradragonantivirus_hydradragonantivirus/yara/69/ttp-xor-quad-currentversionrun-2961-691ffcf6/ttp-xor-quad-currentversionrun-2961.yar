rule TTP_XOR_QUAD_CurrentVersionRun_2961 {
  strings:
    $key_2961 = { 7a 0e [2] 5e 00 [2] 75 2c [2] 5b 0e [2] 4f 15 [2] 40 0f [2] 5e 12 [2] 5c 13 [2] 47 15 [2] 5b 12 [2] 47 3d }

  condition:
    any of them
}