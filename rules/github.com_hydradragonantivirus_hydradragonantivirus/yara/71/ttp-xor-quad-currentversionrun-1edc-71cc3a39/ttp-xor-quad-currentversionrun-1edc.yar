rule TTP_XOR_QUAD_CurrentVersionRun_1edc {
  strings:
    $key_1edc = { 4d b3 [2] 69 bd [2] 42 91 [2] 6c b3 [2] 78 a8 [2] 77 b2 [2] 69 af [2] 6b ae [2] 70 a8 [2] 6c af [2] 70 80 }

  condition:
    any of them
}