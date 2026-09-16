rule TTP_XOR_QUAD_CurrentVersionRun_eb5c {
  strings:
    $key_eb5c = { b8 33 [2] 9c 3d [2] b7 11 [2] 99 33 [2] 8d 28 [2] 82 32 [2] 9c 2f [2] 9e 2e [2] 85 28 [2] 99 2f [2] 85 00 }

  condition:
    any of them
}