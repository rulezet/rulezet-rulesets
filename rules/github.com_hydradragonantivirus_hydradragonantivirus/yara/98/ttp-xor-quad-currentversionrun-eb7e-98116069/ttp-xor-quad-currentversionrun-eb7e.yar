rule TTP_XOR_QUAD_CurrentVersionRun_eb7e {
  strings:
    $key_eb7e = { b8 11 [2] 9c 1f [2] b7 33 [2] 99 11 [2] 8d 0a [2] 82 10 [2] 9c 0d [2] 9e 0c [2] 85 0a [2] 99 0d [2] 85 22 }

  condition:
    any of them
}