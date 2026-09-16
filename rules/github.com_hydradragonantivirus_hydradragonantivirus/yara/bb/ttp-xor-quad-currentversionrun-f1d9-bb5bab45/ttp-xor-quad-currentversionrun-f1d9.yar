rule TTP_XOR_QUAD_CurrentVersionRun_f1d9 {
  strings:
    $key_f1d9 = { a2 b6 [2] 86 b8 [2] ad 94 [2] 83 b6 [2] 97 ad [2] 98 b7 [2] 86 aa [2] 84 ab [2] 9f ad [2] 83 aa [2] 9f 85 }

  condition:
    any of them
}