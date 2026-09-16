rule TTP_XOR_QUAD_CurrentVersionRun_eb1e {
  strings:
    $key_eb1e = { b8 71 [2] 9c 7f [2] b7 53 [2] 99 71 [2] 8d 6a [2] 82 70 [2] 9c 6d [2] 9e 6c [2] 85 6a [2] 99 6d [2] 85 42 }

  condition:
    any of them
}