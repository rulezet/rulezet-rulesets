rule TTP_XOR_QUAD_CurrentVersionRun_bec0 {
  strings:
    $key_bec0 = { ed af [2] c9 a1 [2] e2 8d [2] cc af [2] d8 b4 [2] d7 ae [2] c9 b3 [2] cb b2 [2] d0 b4 [2] cc b3 [2] d0 9c }

  condition:
    any of them
}