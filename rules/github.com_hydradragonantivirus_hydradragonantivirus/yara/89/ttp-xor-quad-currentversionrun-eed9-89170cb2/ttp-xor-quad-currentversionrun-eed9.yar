rule TTP_XOR_QUAD_CurrentVersionRun_eed9 {
  strings:
    $key_eed9 = { bd b6 [2] 99 b8 [2] b2 94 [2] 9c b6 [2] 88 ad [2] 87 b7 [2] 99 aa [2] 9b ab [2] 80 ad [2] 9c aa [2] 80 85 }

  condition:
    any of them
}