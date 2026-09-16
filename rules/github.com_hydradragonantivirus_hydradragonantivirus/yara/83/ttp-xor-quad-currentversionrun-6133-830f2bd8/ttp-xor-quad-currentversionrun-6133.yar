rule TTP_XOR_QUAD_CurrentVersionRun_6133 {
  strings:
    $key_6133 = { 32 5c [2] 16 52 [2] 3d 7e [2] 13 5c [2] 07 47 [2] 08 5d [2] 16 40 [2] 14 41 [2] 0f 47 [2] 13 40 [2] 0f 6f }

  condition:
    any of them
}