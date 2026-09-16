rule TTP_XOR_QUAD_CurrentVersionRun_e938 {
  strings:
    $key_e938 = { ba 57 [2] 9e 59 [2] b5 75 [2] 9b 57 [2] 8f 4c [2] 80 56 [2] 9e 4b [2] 9c 4a [2] 87 4c [2] 9b 4b [2] 87 64 }

  condition:
    any of them
}