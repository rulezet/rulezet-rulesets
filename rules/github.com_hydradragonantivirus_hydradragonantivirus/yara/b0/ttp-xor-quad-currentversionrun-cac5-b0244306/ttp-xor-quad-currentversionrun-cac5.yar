rule TTP_XOR_QUAD_CurrentVersionRun_cac5 {
  strings:
    $key_cac5 = { 99 aa [2] bd a4 [2] 96 88 [2] b8 aa [2] ac b1 [2] a3 ab [2] bd b6 [2] bf b7 [2] a4 b1 [2] b8 b6 [2] a4 99 }

  condition:
    any of them
}