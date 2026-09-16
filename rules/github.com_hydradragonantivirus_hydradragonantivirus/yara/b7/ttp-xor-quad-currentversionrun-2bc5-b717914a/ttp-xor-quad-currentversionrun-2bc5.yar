rule TTP_XOR_QUAD_CurrentVersionRun_2bc5 {
  strings:
    $key_2bc5 = { 78 aa [2] 5c a4 [2] 77 88 [2] 59 aa [2] 4d b1 [2] 42 ab [2] 5c b6 [2] 5e b7 [2] 45 b1 [2] 59 b6 [2] 45 99 }

  condition:
    any of them
}