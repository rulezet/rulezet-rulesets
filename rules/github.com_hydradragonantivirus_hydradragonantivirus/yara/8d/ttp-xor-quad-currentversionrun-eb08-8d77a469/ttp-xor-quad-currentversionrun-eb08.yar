rule TTP_XOR_QUAD_CurrentVersionRun_eb08 {
  strings:
    $key_eb08 = { b8 67 [2] 9c 69 [2] b7 45 [2] 99 67 [2] 8d 7c [2] 82 66 [2] 9c 7b [2] 9e 7a [2] 85 7c [2] 99 7b [2] 85 54 }

  condition:
    any of them
}