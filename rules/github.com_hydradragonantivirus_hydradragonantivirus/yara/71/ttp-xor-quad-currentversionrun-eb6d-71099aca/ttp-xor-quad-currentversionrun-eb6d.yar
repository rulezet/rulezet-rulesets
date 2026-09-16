rule TTP_XOR_QUAD_CurrentVersionRun_eb6d {
  strings:
    $key_eb6d = { b8 02 [2] 9c 0c [2] b7 20 [2] 99 02 [2] 8d 19 [2] 82 03 [2] 9c 1e [2] 9e 1f [2] 85 19 [2] 99 1e [2] 85 31 }

  condition:
    any of them
}