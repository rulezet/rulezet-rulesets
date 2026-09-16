rule TTP_XOR_QUAD_CurrentVersionRun_93dc {
  strings:
    $key_93dc = { c0 b3 [2] e4 bd [2] cf 91 [2] e1 b3 [2] f5 a8 [2] fa b2 [2] e4 af [2] e6 ae [2] fd a8 [2] e1 af [2] fd 80 }

  condition:
    any of them
}