rule TTP_XOR_QUAD_CurrentVersionRun_61c0 {
  strings:
    $key_61c0 = { 32 af [2] 16 a1 [2] 3d 8d [2] 13 af [2] 07 b4 [2] 08 ae [2] 16 b3 [2] 14 b2 [2] 0f b4 [2] 13 b3 [2] 0f 9c }

  condition:
    any of them
}