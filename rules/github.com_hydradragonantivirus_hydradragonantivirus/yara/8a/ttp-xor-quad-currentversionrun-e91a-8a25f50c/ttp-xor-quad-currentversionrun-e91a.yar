rule TTP_XOR_QUAD_CurrentVersionRun_e91a {
  strings:
    $key_e91a = { ba 75 [2] 9e 7b [2] b5 57 [2] 9b 75 [2] 8f 6e [2] 80 74 [2] 9e 69 [2] 9c 68 [2] 87 6e [2] 9b 69 [2] 87 46 }

  condition:
    any of them
}