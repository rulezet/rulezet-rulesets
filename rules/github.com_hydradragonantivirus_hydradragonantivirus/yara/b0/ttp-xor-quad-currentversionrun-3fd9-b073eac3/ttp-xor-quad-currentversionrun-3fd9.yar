rule TTP_XOR_QUAD_CurrentVersionRun_3fd9 {
  strings:
    $key_3fd9 = { 6c b6 [2] 48 b8 [2] 63 94 [2] 4d b6 [2] 59 ad [2] 56 b7 [2] 48 aa [2] 4a ab [2] 51 ad [2] 4d aa [2] 51 85 }

  condition:
    any of them
}