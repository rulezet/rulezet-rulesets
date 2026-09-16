rule TTP_XOR_QUAD_CurrentVersionRun_a1d9 {
  strings:
    $key_a1d9 = { f2 b6 [2] d6 b8 [2] fd 94 [2] d3 b6 [2] c7 ad [2] c8 b7 [2] d6 aa [2] d4 ab [2] cf ad [2] d3 aa [2] cf 85 }

  condition:
    any of them
}