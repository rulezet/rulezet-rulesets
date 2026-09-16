rule TTP_XOR_QUAD_CurrentVersionRun_e915 {
  strings:
    $key_e915 = { ba 7a [2] 9e 74 [2] b5 58 [2] 9b 7a [2] 8f 61 [2] 80 7b [2] 9e 66 [2] 9c 67 [2] 87 61 [2] 9b 66 [2] 87 49 }

  condition:
    any of them
}