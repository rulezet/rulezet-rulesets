rule TTP_XOR_QUAD_CurrentVersionRun_0edc {
  strings:
    $key_0edc = { 5d b3 [2] 79 bd [2] 52 91 [2] 7c b3 [2] 68 a8 [2] 67 b2 [2] 79 af [2] 7b ae [2] 60 a8 [2] 7c af [2] 60 80 }

  condition:
    any of them
}