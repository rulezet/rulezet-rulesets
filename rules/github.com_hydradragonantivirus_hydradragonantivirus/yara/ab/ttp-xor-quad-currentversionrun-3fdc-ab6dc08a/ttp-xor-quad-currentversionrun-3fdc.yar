rule TTP_XOR_QUAD_CurrentVersionRun_3fdc {
  strings:
    $key_3fdc = { 6c b3 [2] 48 bd [2] 63 91 [2] 4d b3 [2] 59 a8 [2] 56 b2 [2] 48 af [2] 4a ae [2] 51 a8 [2] 4d af [2] 51 80 }

  condition:
    any of them
}