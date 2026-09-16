rule TTP_XOR_QUAD_CurrentVersionRun_e900 {
  strings:
    $key_e900 = { ba 6f [2] 9e 61 [2] b5 4d [2] 9b 6f [2] 8f 74 [2] 80 6e [2] 9e 73 [2] 9c 72 [2] 87 74 [2] 9b 73 [2] 87 5c }

  condition:
    any of them
}