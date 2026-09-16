rule TTP_XOR_QUAD_CurrentVersionRun_37d9 {
  strings:
    $key_37d9 = { 64 b6 [2] 40 b8 [2] 6b 94 [2] 45 b6 [2] 51 ad [2] 5e b7 [2] 40 aa [2] 42 ab [2] 59 ad [2] 45 aa [2] 59 85 }

  condition:
    any of them
}