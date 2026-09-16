rule TTP_XOR_QUAD_CurrentVersionRun_21d9 {
  strings:
    $key_21d9 = { 72 b6 [2] 56 b8 [2] 7d 94 [2] 53 b6 [2] 47 ad [2] 48 b7 [2] 56 aa [2] 54 ab [2] 4f ad [2] 53 aa [2] 4f 85 }

  condition:
    any of them
}