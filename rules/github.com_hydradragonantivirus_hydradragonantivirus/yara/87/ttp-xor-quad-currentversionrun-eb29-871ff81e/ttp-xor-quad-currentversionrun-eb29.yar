rule TTP_XOR_QUAD_CurrentVersionRun_eb29 {
  strings:
    $key_eb29 = { b8 46 [2] 9c 48 [2] b7 64 [2] 99 46 [2] 8d 5d [2] 82 47 [2] 9c 5a [2] 9e 5b [2] 85 5d [2] 99 5a [2] 85 75 }

  condition:
    any of them
}