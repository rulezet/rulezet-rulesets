rule TTP_XOR_QUAD_CurrentVersionRun_7ad9 {
  strings:
    $key_7ad9 = { 29 b6 [2] 0d b8 [2] 26 94 [2] 08 b6 [2] 1c ad [2] 13 b7 [2] 0d aa [2] 0f ab [2] 14 ad [2] 08 aa [2] 14 85 }

  condition:
    any of them
}