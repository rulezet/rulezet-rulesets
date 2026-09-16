rule TTP_XOR_QUAD_CurrentVersionRun_89d9 {
  strings:
    $key_89d9 = { da b6 [2] fe b8 [2] d5 94 [2] fb b6 [2] ef ad [2] e0 b7 [2] fe aa [2] fc ab [2] e7 ad [2] fb aa [2] e7 85 }

  condition:
    any of them
}