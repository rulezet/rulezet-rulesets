rule TTP_XOR_QUAD_CurrentVersionRun_9ddd {
  strings:
    $key_9ddd = { ce b2 [2] ea bc [2] c1 90 [2] ef b2 [2] fb a9 [2] f4 b3 [2] ea ae [2] e8 af [2] f3 a9 [2] ef ae [2] f3 81 }

  condition:
    any of them
}