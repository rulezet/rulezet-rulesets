rule TTP_XOR_QUAD_CurrentVersionRun_2d01 {
  strings:
    $key_2d01 = { 7e 6e [2] 5a 60 [2] 71 4c [2] 5f 6e [2] 4b 75 [2] 44 6f [2] 5a 72 [2] 58 73 [2] 43 75 [2] 5f 72 [2] 43 5d }

  condition:
    any of them
}