rule TTP_XOR_QUAD_CurrentVersionRun_eb4b {
  strings:
    $key_eb4b = { b8 24 [2] 9c 2a [2] b7 06 [2] 99 24 [2] 8d 3f [2] 82 25 [2] 9c 38 [2] 9e 39 [2] 85 3f [2] 99 38 [2] 85 17 }

  condition:
    any of them
}