rule TTP_XOR_QUAD_CurrentVersionRun_b0d9 {
  strings:
    $key_b0d9 = { e3 b6 [2] c7 b8 [2] ec 94 [2] c2 b6 [2] d6 ad [2] d9 b7 [2] c7 aa [2] c5 ab [2] de ad [2] c2 aa [2] de 85 }

  condition:
    any of them
}