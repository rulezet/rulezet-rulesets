rule TTP_XOR_QUAD_CurrentVersionRun_33c5 {
  strings:
    $key_33c5 = { 60 aa [2] 44 a4 [2] 6f 88 [2] 41 aa [2] 55 b1 [2] 5a ab [2] 44 b6 [2] 46 b7 [2] 5d b1 [2] 41 b6 [2] 5d 99 }

  condition:
    any of them
}