rule TTP_XOR_QUAD_CurrentVersionRun_eb49 {
  strings:
    $key_eb49 = { b8 26 [2] 9c 28 [2] b7 04 [2] 99 26 [2] 8d 3d [2] 82 27 [2] 9c 3a [2] 9e 3b [2] 85 3d [2] 99 3a [2] 85 15 }

  condition:
    any of them
}