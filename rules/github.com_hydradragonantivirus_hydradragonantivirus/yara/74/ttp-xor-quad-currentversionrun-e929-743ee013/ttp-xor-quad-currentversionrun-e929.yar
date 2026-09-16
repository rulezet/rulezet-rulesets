rule TTP_XOR_QUAD_CurrentVersionRun_e929 {
  strings:
    $key_e929 = { ba 46 [2] 9e 48 [2] b5 64 [2] 9b 46 [2] 8f 5d [2] 80 47 [2] 9e 5a [2] 9c 5b [2] 87 5d [2] 9b 5a [2] 87 75 }

  condition:
    any of them
}