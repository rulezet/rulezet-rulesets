rule TTP_XOR_QUAD_CurrentVersionRun_e932 {
  strings:
    $key_e932 = { ba 5d [2] 9e 53 [2] b5 7f [2] 9b 5d [2] 8f 46 [2] 80 5c [2] 9e 41 [2] 9c 40 [2] 87 46 [2] 9b 41 [2] 87 6e }

  condition:
    any of them
}