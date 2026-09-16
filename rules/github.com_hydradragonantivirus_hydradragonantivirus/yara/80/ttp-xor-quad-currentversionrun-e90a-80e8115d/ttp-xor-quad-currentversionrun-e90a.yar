rule TTP_XOR_QUAD_CurrentVersionRun_e90a {
  strings:
    $key_e90a = { ba 65 [2] 9e 6b [2] b5 47 [2] 9b 65 [2] 8f 7e [2] 80 64 [2] 9e 79 [2] 9c 78 [2] 87 7e [2] 9b 79 [2] 87 56 }

  condition:
    any of them
}