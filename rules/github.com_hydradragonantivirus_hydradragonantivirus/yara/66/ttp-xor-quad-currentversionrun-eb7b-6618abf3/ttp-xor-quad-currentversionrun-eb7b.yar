rule TTP_XOR_QUAD_CurrentVersionRun_eb7b {
  strings:
    $key_eb7b = { b8 14 [2] 9c 1a [2] b7 36 [2] 99 14 [2] 8d 0f [2] 82 15 [2] 9c 08 [2] 9e 09 [2] 85 0f [2] 99 08 [2] 85 27 }

  condition:
    any of them
}