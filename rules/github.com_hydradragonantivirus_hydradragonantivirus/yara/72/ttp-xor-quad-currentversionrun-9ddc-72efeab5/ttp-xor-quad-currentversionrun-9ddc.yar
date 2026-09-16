rule TTP_XOR_QUAD_CurrentVersionRun_9ddc {
  strings:
    $key_9ddc = { ce b3 [2] ea bd [2] c1 91 [2] ef b3 [2] fb a8 [2] f4 b2 [2] ea af [2] e8 ae [2] f3 a8 [2] ef af [2] f3 80 }

  condition:
    any of them
}