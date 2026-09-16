rule TTP_XOR_QUAD_CurrentVersionRun_bedc {
  strings:
    $key_bedc = { ed b3 [2] c9 bd [2] e2 91 [2] cc b3 [2] d8 a8 [2] d7 b2 [2] c9 af [2] cb ae [2] d0 a8 [2] cc af [2] d0 80 }

  condition:
    any of them
}