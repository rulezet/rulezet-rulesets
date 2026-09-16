rule TTP_XOR_QUAD_CurrentVersionRun_32c5 {
  strings:
    $key_32c5 = { 61 aa [2] 45 a4 [2] 6e 88 [2] 40 aa [2] 54 b1 [2] 5b ab [2] 45 b6 [2] 47 b7 [2] 5c b1 [2] 40 b6 [2] 5c 99 }

  condition:
    any of them
}