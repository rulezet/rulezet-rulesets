rule TTP_XOR_QUAD_CurrentVersionRun_e902 {
  strings:
    $key_e902 = { ba 6d [2] 9e 63 [2] b5 4f [2] 9b 6d [2] 8f 76 [2] 80 6c [2] 9e 71 [2] 9c 70 [2] 87 76 [2] 9b 71 [2] 87 5e }

  condition:
    any of them
}