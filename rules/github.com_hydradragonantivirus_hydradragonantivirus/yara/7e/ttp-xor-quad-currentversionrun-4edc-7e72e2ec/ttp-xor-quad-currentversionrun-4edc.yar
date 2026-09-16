rule TTP_XOR_QUAD_CurrentVersionRun_4edc {
  strings:
    $key_4edc = { 1d b3 [2] 39 bd [2] 12 91 [2] 3c b3 [2] 28 a8 [2] 27 b2 [2] 39 af [2] 3b ae [2] 20 a8 [2] 3c af [2] 20 80 }

  condition:
    any of them
}