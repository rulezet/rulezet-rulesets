rule TTP_XOR_QUAD_CurrentVersionRun_2edc {
  strings:
    $key_2edc = { 7d b3 [2] 59 bd [2] 72 91 [2] 5c b3 [2] 48 a8 [2] 47 b2 [2] 59 af [2] 5b ae [2] 40 a8 [2] 5c af [2] 40 80 }

  condition:
    any of them
}