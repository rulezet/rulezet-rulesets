rule TTP_XOR_QUAD_CurrentVersionRun_eb54 {
  strings:
    $key_eb54 = { b8 3b [2] 9c 35 [2] b7 19 [2] 99 3b [2] 8d 20 [2] 82 3a [2] 9c 27 [2] 9e 26 [2] 85 20 [2] 99 27 [2] 85 08 }

  condition:
    any of them
}