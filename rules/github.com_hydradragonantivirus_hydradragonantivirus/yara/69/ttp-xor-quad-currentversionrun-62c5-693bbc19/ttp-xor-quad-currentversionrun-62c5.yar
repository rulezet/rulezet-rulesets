rule TTP_XOR_QUAD_CurrentVersionRun_62c5 {
  strings:
    $key_62c5 = { 31 aa [2] 15 a4 [2] 3e 88 [2] 10 aa [2] 04 b1 [2] 0b ab [2] 15 b6 [2] 17 b7 [2] 0c b1 [2] 10 b6 [2] 0c 99 }

  condition:
    any of them
}