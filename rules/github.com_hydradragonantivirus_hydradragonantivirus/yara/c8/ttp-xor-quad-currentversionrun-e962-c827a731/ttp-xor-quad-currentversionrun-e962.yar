rule TTP_XOR_QUAD_CurrentVersionRun_e962 {
  strings:
    $key_e962 = { ba 0d [2] 9e 03 [2] b5 2f [2] 9b 0d [2] 8f 16 [2] 80 0c [2] 9e 11 [2] 9c 10 [2] 87 16 [2] 9b 11 [2] 87 3e }

  condition:
    any of them
}