rule TTP_XOR_QUAD_CurrentVersionRun_cadc {
  strings:
    $key_cadc = { 99 b3 [2] bd bd [2] 96 91 [2] b8 b3 [2] ac a8 [2] a3 b2 [2] bd af [2] bf ae [2] a4 a8 [2] b8 af [2] a4 80 }

  condition:
    any of them
}