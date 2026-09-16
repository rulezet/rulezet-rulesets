rule TTP_XOR_QUAD_CurrentVersionRun_f1c5 {
  strings:
    $key_f1c5 = { a2 aa [2] 86 a4 [2] ad 88 [2] 83 aa [2] 97 b1 [2] 98 ab [2] 86 b6 [2] 84 b7 [2] 9f b1 [2] 83 b6 [2] 9f 99 }

  condition:
    any of them
}