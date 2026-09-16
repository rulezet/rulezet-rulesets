rule TTP_XOR_QUAD_CurrentVersionRun_20c5 {
  strings:
    $key_20c5 = { 73 aa [2] 57 a4 [2] 7c 88 [2] 52 aa [2] 46 b1 [2] 49 ab [2] 57 b6 [2] 55 b7 [2] 4e b1 [2] 52 b6 [2] 4e 99 }

  condition:
    any of them
}