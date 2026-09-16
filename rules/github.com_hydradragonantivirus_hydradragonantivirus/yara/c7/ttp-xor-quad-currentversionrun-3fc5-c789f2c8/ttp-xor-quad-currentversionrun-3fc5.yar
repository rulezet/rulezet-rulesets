rule TTP_XOR_QUAD_CurrentVersionRun_3fc5 {
  strings:
    $key_3fc5 = { 6c aa [2] 48 a4 [2] 63 88 [2] 4d aa [2] 59 b1 [2] 56 ab [2] 48 b6 [2] 4a b7 [2] 51 b1 [2] 4d b6 [2] 51 99 }

  condition:
    any of them
}