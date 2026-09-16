rule TTP_XOR_QUAD_CurrentVersionRun_6fdc {
  strings:
    $key_6fdc = { 3c b3 [2] 18 bd [2] 33 91 [2] 1d b3 [2] 09 a8 [2] 06 b2 [2] 18 af [2] 1a ae [2] 01 a8 [2] 1d af [2] 01 80 }

  condition:
    any of them
}