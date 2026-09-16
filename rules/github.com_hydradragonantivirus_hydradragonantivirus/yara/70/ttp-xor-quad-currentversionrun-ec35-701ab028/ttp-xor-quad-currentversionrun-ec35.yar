rule TTP_XOR_QUAD_CurrentVersionRun_ec35 {
  strings:
    $key_ec35 = { bf 5a [2] 9b 54 [2] b0 78 [2] 9e 5a [2] 8a 41 [2] 85 5b [2] 9b 46 [2] 99 47 [2] 82 41 [2] 9e 46 [2] 82 69 }

  condition:
    any of them
}