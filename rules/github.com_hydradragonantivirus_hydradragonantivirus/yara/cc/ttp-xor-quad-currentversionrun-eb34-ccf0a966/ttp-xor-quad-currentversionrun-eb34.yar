rule TTP_XOR_QUAD_CurrentVersionRun_eb34 {
  strings:
    $key_eb34 = { b8 5b [2] 9c 55 [2] b7 79 [2] 99 5b [2] 8d 40 [2] 82 5a [2] 9c 47 [2] 9e 46 [2] 85 40 [2] 99 47 [2] 85 68 }

  condition:
    any of them
}