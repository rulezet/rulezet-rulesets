rule TTP_XOR_QUAD_CurrentVersionRun_e950 {
  strings:
    $key_e950 = { ba 3f [2] 9e 31 [2] b5 1d [2] 9b 3f [2] 8f 24 [2] 80 3e [2] 9e 23 [2] 9c 22 [2] 87 24 [2] 9b 23 [2] 87 0c }

  condition:
    any of them
}