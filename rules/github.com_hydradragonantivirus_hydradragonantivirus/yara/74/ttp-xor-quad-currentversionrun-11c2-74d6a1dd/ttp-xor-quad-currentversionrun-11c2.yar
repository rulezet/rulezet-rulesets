rule TTP_XOR_QUAD_CurrentVersionRun_11c2 {
  strings:
    $key_11c2 = { 42 ad [2] 66 a3 [2] 4d 8f [2] 63 ad [2] 77 b6 [2] 78 ac [2] 66 b1 [2] 64 b0 [2] 7f b6 [2] 63 b1 [2] 7f 9e }

  condition:
    any of them
}