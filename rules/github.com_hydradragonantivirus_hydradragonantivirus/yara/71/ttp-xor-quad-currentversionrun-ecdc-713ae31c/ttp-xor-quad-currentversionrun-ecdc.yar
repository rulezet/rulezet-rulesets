rule TTP_XOR_QUAD_CurrentVersionRun_ecdc {
  strings:
    $key_ecdc = { bf b3 [2] 9b bd [2] b0 91 [2] 9e b3 [2] 8a a8 [2] 85 b2 [2] 9b af [2] 99 ae [2] 82 a8 [2] 9e af [2] 82 80 }

  condition:
    any of them
}