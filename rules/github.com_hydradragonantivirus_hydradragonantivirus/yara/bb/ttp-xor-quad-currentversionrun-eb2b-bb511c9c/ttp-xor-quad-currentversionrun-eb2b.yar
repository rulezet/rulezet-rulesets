rule TTP_XOR_QUAD_CurrentVersionRun_eb2b {
  strings:
    $key_eb2b = { b8 44 [2] 9c 4a [2] b7 66 [2] 99 44 [2] 8d 5f [2] 82 45 [2] 9c 58 [2] 9e 59 [2] 85 5f [2] 99 58 [2] 85 77 }

  condition:
    any of them
}