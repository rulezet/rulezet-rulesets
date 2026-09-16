rule TTP_XOR_QUAD_CurrentVersionRun_e926 {
  strings:
    $key_e926 = { ba 49 [2] 9e 47 [2] b5 6b [2] 9b 49 [2] 8f 52 [2] 80 48 [2] 9e 55 [2] 9c 54 [2] 87 52 [2] 9b 55 [2] 87 7a }

  condition:
    any of them
}