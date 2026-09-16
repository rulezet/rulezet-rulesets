rule TTP_XOR_QUAD_CurrentVersionRun_eb65 {
  strings:
    $key_eb65 = { b8 0a [2] 9c 04 [2] b7 28 [2] 99 0a [2] 8d 11 [2] 82 0b [2] 9c 16 [2] 9e 17 [2] 85 11 [2] 99 16 [2] 85 39 }

  condition:
    any of them
}