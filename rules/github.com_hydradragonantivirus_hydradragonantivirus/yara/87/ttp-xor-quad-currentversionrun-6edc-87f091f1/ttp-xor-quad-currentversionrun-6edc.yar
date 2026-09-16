rule TTP_XOR_QUAD_CurrentVersionRun_6edc {
  strings:
    $key_6edc = { 3d b3 [2] 19 bd [2] 32 91 [2] 1c b3 [2] 08 a8 [2] 07 b2 [2] 19 af [2] 1b ae [2] 00 a8 [2] 1c af [2] 00 80 }

  condition:
    any of them
}