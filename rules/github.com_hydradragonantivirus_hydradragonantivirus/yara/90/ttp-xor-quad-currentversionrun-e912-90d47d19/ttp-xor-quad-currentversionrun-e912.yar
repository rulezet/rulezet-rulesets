rule TTP_XOR_QUAD_CurrentVersionRun_e912 {
  strings:
    $key_e912 = { ba 7d [2] 9e 73 [2] b5 5f [2] 9b 7d [2] 8f 66 [2] 80 7c [2] 9e 61 [2] 9c 60 [2] 87 66 [2] 9b 61 [2] 87 4e }

  condition:
    any of them
}