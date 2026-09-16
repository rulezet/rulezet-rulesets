rule TTP_XOR_QUAD_CurrentVersionRun_62d9 {
  strings:
    $key_62d9 = { 31 b6 [2] 15 b8 [2] 3e 94 [2] 10 b6 [2] 04 ad [2] 0b b7 [2] 15 aa [2] 17 ab [2] 0c ad [2] 10 aa [2] 0c 85 }

  condition:
    any of them
}