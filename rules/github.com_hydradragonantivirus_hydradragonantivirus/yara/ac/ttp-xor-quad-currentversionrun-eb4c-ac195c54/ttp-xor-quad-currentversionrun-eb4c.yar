rule TTP_XOR_QUAD_CurrentVersionRun_eb4c {
  strings:
    $key_eb4c = { b8 23 [2] 9c 2d [2] b7 01 [2] 99 23 [2] 8d 38 [2] 82 22 [2] 9c 3f [2] 9e 3e [2] 85 38 [2] 99 3f [2] 85 10 }

  condition:
    any of them
}