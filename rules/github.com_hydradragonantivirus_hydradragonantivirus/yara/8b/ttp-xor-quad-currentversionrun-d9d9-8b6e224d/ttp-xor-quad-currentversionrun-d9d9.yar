rule TTP_XOR_QUAD_CurrentVersionRun_d9d9 {
  strings:
    $key_d9d9 = { 8a b6 [2] ae b8 [2] 85 94 [2] ab b6 [2] bf ad [2] b0 b7 [2] ae aa [2] ac ab [2] b7 ad [2] ab aa [2] b7 85 }

  condition:
    any of them
}