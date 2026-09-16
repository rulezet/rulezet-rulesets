rule TTP_XOR_QUAD_CurrentVersionRun_e907 {
  strings:
    $key_e907 = { ba 68 [2] 9e 66 [2] b5 4a [2] 9b 68 [2] 8f 73 [2] 80 69 [2] 9e 74 [2] 9c 75 [2] 87 73 [2] 9b 74 [2] 87 5b }

  condition:
    any of them
}