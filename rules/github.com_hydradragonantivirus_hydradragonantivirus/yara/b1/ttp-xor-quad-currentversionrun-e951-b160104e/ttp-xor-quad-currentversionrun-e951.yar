rule TTP_XOR_QUAD_CurrentVersionRun_e951 {
  strings:
    $key_e951 = { ba 3e [2] 9e 30 [2] b5 1c [2] 9b 3e [2] 8f 25 [2] 80 3f [2] 9e 22 [2] 9c 23 [2] 87 25 [2] 9b 22 [2] 87 0d }

  condition:
    any of them
}