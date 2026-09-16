rule TTP_XOR_QUAD_CurrentVersionRun_05d9 {
  strings:
    $key_05d9 = { 56 b6 [2] 72 b8 [2] 59 94 [2] 77 b6 [2] 63 ad [2] 6c b7 [2] 72 aa [2] 70 ab [2] 6b ad [2] 77 aa [2] 6b 85 }

  condition:
    any of them
}