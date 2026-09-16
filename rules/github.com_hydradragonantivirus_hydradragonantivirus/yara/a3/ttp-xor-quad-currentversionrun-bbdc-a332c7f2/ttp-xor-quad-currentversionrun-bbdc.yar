rule TTP_XOR_QUAD_CurrentVersionRun_bbdc {
  strings:
    $key_bbdc = { e8 b3 [2] cc bd [2] e7 91 [2] c9 b3 [2] dd a8 [2] d2 b2 [2] cc af [2] ce ae [2] d5 a8 [2] c9 af [2] d5 80 }

  condition:
    any of them
}