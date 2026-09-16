rule TTP_XOR_QUAD_CurrentVersionRun_3927 {
  strings:
    $key_3927 = { 6a 48 [2] 4e 46 [2] 65 6a [2] 4b 48 [2] 5f 53 [2] 50 49 [2] 4e 54 [2] 4c 55 [2] 57 53 [2] 4b 54 [2] 57 7b }

  condition:
    any of them
}