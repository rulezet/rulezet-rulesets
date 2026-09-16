rule TTP_XOR_QUAD_CurrentVersionRun_89dc {
  strings:
    $key_89dc = { da b3 [2] fe bd [2] d5 91 [2] fb b3 [2] ef a8 [2] e0 b2 [2] fe af [2] fc ae [2] e7 a8 [2] fb af [2] e7 80 }

  condition:
    any of them
}