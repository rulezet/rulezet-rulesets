rule TTP_XOR_QUAD_CurrentVersionRun_eb05 {
  strings:
    $key_eb05 = { b8 6a [2] 9c 64 [2] b7 48 [2] 99 6a [2] 8d 71 [2] 82 6b [2] 9c 76 [2] 9e 77 [2] 85 71 [2] 99 76 [2] 85 59 }

  condition:
    any of them
}