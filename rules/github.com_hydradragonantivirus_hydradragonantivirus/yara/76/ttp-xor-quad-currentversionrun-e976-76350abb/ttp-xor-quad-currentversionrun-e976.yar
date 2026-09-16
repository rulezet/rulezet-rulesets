rule TTP_XOR_QUAD_CurrentVersionRun_e976 {
  strings:
    $key_e976 = { ba 19 [2] 9e 17 [2] b5 3b [2] 9b 19 [2] 8f 02 [2] 80 18 [2] 9e 05 [2] 9c 04 [2] 87 02 [2] 9b 05 [2] 87 2a }

  condition:
    any of them
}