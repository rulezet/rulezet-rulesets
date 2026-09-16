rule TTP_XOR_QUAD_CurrentVersionRun_6ec1 {
  strings:
    $key_6ec1 = { 3d ae [2] 19 a0 [2] 32 8c [2] 1c ae [2] 08 b5 [2] 07 af [2] 19 b2 [2] 1b b3 [2] 00 b5 [2] 1c b2 [2] 00 9d }

  condition:
    any of them
}