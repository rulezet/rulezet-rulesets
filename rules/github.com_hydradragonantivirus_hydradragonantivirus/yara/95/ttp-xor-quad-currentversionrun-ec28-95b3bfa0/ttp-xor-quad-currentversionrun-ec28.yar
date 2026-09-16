rule TTP_XOR_QUAD_CurrentVersionRun_ec28 {
  strings:
    $key_ec28 = { bf 47 [2] 9b 49 [2] b0 65 [2] 9e 47 [2] 8a 5c [2] 85 46 [2] 9b 5b [2] 99 5a [2] 82 5c [2] 9e 5b [2] 82 74 }

  condition:
    any of them
}