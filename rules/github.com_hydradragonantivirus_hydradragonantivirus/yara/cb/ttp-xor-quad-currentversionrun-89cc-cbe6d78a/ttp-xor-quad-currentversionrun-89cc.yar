rule TTP_XOR_QUAD_CurrentVersionRun_89cc {
  strings:
    $key_89cc = { da a3 [2] fe ad [2] d5 81 [2] fb a3 [2] ef b8 [2] e0 a2 [2] fe bf [2] fc be [2] e7 b8 [2] fb bf [2] e7 90 }

  condition:
    any of them
}