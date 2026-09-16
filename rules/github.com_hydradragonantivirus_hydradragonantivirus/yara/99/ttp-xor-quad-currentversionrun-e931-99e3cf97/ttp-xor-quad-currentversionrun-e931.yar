rule TTP_XOR_QUAD_CurrentVersionRun_e931 {
  strings:
    $key_e931 = { ba 5e [2] 9e 50 [2] b5 7c [2] 9b 5e [2] 8f 45 [2] 80 5f [2] 9e 42 [2] 9c 43 [2] 87 45 [2] 9b 42 [2] 87 6d }

  condition:
    any of them
}