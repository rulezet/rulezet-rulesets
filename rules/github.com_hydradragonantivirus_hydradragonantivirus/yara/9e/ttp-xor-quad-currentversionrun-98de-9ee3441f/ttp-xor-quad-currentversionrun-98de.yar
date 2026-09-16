rule TTP_XOR_QUAD_CurrentVersionRun_98de {
  strings:
    $key_98de = { cb b1 [2] ef bf [2] c4 93 [2] ea b1 [2] fe aa [2] f1 b0 [2] ef ad [2] ed ac [2] f6 aa [2] ea ad [2] f6 82 }

  condition:
    any of them
}