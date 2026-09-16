rule TTP_XOR_QUAD_CurrentVersionRun_e97a {
  strings:
    $key_e97a = { ba 15 [2] 9e 1b [2] b5 37 [2] 9b 15 [2] 8f 0e [2] 80 14 [2] 9e 09 [2] 9c 08 [2] 87 0e [2] 9b 09 [2] 87 26 }

  condition:
    any of them
}