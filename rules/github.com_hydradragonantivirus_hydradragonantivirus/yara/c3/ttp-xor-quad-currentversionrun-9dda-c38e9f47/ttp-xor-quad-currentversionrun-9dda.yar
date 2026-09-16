rule TTP_XOR_QUAD_CurrentVersionRun_9dda {
  strings:
    $key_9dda = { ce b5 [2] ea bb [2] c1 97 [2] ef b5 [2] fb ae [2] f4 b4 [2] ea a9 [2] e8 a8 [2] f3 ae [2] ef a9 [2] f3 86 }

  condition:
    any of them
}