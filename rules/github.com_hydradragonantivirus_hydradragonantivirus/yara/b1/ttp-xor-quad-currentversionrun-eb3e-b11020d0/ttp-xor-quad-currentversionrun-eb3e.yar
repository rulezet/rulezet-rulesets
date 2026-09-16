rule TTP_XOR_QUAD_CurrentVersionRun_eb3e {
  strings:
    $key_eb3e = { b8 51 [2] 9c 5f [2] b7 73 [2] 99 51 [2] 8d 4a [2] 82 50 [2] 9c 4d [2] 9e 4c [2] 85 4a [2] 99 4d [2] 85 62 }

  condition:
    any of them
}