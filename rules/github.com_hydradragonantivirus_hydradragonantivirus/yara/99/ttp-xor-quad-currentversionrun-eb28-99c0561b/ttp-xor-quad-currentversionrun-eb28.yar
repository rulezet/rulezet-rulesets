rule TTP_XOR_QUAD_CurrentVersionRun_eb28 {
  strings:
    $key_eb28 = { b8 47 [2] 9c 49 [2] b7 65 [2] 99 47 [2] 8d 5c [2] 82 46 [2] 9c 5b [2] 9e 5a [2] 85 5c [2] 99 5b [2] 85 74 }

  condition:
    any of them
}