rule TTP_XOR_QUAD_CurrentVersionRun_3a28 {
  strings:
    $key_3a28 = { 69 47 [2] 4d 49 [2] 66 65 [2] 48 47 [2] 5c 5c [2] 53 46 [2] 4d 5b [2] 4f 5a [2] 54 5c [2] 48 5b [2] 54 74 }

  condition:
    any of them
}