rule TTP_XOR_QUAD_CurrentVersionRun_ebc5 {
  strings:
    $key_ebc5 = { b8 aa [2] 9c a4 [2] b7 88 [2] 99 aa [2] 8d b1 [2] 82 ab [2] 9c b6 [2] 9e b7 [2] 85 b1 [2] 99 b6 [2] 85 99 }

  condition:
    any of them
}