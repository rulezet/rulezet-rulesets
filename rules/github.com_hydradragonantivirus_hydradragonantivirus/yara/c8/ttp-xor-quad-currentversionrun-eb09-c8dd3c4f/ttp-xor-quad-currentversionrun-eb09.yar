rule TTP_XOR_QUAD_CurrentVersionRun_eb09 {
  strings:
    $key_eb09 = { b8 66 [2] 9c 68 [2] b7 44 [2] 99 66 [2] 8d 7d [2] 82 67 [2] 9c 7a [2] 9e 7b [2] 85 7d [2] 99 7a [2] 85 55 }

  condition:
    any of them
}