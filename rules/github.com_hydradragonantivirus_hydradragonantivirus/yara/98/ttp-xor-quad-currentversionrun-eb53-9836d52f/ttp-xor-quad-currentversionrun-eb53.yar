rule TTP_XOR_QUAD_CurrentVersionRun_eb53 {
  strings:
    $key_eb53 = { b8 3c [2] 9c 32 [2] b7 1e [2] 99 3c [2] 8d 27 [2] 82 3d [2] 9c 20 [2] 9e 21 [2] 85 27 [2] 99 20 [2] 85 0f }

  condition:
    any of them
}