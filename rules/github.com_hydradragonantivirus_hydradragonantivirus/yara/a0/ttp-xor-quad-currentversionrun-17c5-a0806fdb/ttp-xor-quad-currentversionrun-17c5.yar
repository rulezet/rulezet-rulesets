rule TTP_XOR_QUAD_CurrentVersionRun_17c5 {
  strings:
    $key_17c5 = { 44 aa [2] 60 a4 [2] 4b 88 [2] 65 aa [2] 71 b1 [2] 7e ab [2] 60 b6 [2] 62 b7 [2] 79 b1 [2] 65 b6 [2] 79 99 }

  condition:
    any of them
}