rule TTP_XOR_QUAD_CurrentVersionRun_7fdc {
  strings:
    $key_7fdc = { 2c b3 [2] 08 bd [2] 23 91 [2] 0d b3 [2] 19 a8 [2] 16 b2 [2] 08 af [2] 0a ae [2] 11 a8 [2] 0d af [2] 11 80 }

  condition:
    any of them
}