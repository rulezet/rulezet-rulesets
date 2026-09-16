rule TTP_XOR_QUAD_CurrentVersionRun_fadc {
  strings:
    $key_fadc = { a9 b3 [2] 8d bd [2] a6 91 [2] 88 b3 [2] 9c a8 [2] 93 b2 [2] 8d af [2] 8f ae [2] 94 a8 [2] 88 af [2] 94 80 }

  condition:
    any of them
}