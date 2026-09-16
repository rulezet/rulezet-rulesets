rule TTP_XOR_QUAD_CurrentVersionRun_e952 {
  strings:
    $key_e952 = { ba 3d [2] 9e 33 [2] b5 1f [2] 9b 3d [2] 8f 26 [2] 80 3c [2] 9e 21 [2] 9c 20 [2] 87 26 [2] 9b 21 [2] 87 0e }

  condition:
    any of them
}