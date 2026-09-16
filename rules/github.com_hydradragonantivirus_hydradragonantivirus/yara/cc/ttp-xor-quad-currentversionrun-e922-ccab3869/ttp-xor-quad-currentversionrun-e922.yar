rule TTP_XOR_QUAD_CurrentVersionRun_e922 {
  strings:
    $key_e922 = { ba 4d [2] 9e 43 [2] b5 6f [2] 9b 4d [2] 8f 56 [2] 80 4c [2] 9e 51 [2] 9c 50 [2] 87 56 [2] 9b 51 [2] 87 7e }

  condition:
    any of them
}