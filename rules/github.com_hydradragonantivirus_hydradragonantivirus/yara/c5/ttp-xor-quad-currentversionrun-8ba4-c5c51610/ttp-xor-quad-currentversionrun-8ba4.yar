rule TTP_XOR_QUAD_CurrentVersionRun_8ba4 {
  strings:
    $key_8ba4 = { d8 cb [2] fc c5 [2] d7 e9 [2] f9 cb [2] ed d0 [2] e2 ca [2] fc d7 [2] fe d6 [2] e5 d0 [2] f9 d7 [2] e5 f8 }

  condition:
    any of them
}