rule TTP_XOR_QUAD_CurrentVersionRun_e92c {
  strings:
    $key_e92c = { ba 43 [2] 9e 4d [2] b5 61 [2] 9b 43 [2] 8f 58 [2] 80 42 [2] 9e 5f [2] 9c 5e [2] 87 58 [2] 9b 5f [2] 87 70 }

  condition:
    any of them
}