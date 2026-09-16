rule TTP_XOR_QUAD_CurrentVersionRun_8bd9 {
  strings:
    $key_8bd9 = { d8 b6 [2] fc b8 [2] d7 94 [2] f9 b6 [2] ed ad [2] e2 b7 [2] fc aa [2] fe ab [2] e5 ad [2] f9 aa [2] e5 85 }

  condition:
    any of them
}