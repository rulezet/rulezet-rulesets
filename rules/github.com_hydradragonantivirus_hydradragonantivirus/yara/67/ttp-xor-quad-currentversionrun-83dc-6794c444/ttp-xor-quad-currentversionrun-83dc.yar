rule TTP_XOR_QUAD_CurrentVersionRun_83dc {
  strings:
    $key_83dc = { d0 b3 [2] f4 bd [2] df 91 [2] f1 b3 [2] e5 a8 [2] ea b2 [2] f4 af [2] f6 ae [2] ed a8 [2] f1 af [2] ed 80 }

  condition:
    any of them
}