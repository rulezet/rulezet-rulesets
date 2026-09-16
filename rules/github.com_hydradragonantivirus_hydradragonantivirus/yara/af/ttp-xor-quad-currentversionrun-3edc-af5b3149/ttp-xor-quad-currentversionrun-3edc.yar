rule TTP_XOR_QUAD_CurrentVersionRun_3edc {
  strings:
    $key_3edc = { 6d b3 [2] 49 bd [2] 62 91 [2] 4c b3 [2] 58 a8 [2] 57 b2 [2] 49 af [2] 4b ae [2] 50 a8 [2] 4c af [2] 50 80 }

  condition:
    any of them
}