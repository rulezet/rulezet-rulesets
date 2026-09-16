rule TTP_XOR_QUAD_CurrentVersionRun_ec14 {
  strings:
    $key_ec14 = { bf 7b [2] 9b 75 [2] b0 59 [2] 9e 7b [2] 8a 60 [2] 85 7a [2] 9b 67 [2] 99 66 [2] 82 60 [2] 9e 67 [2] 82 48 }

  condition:
    any of them
}