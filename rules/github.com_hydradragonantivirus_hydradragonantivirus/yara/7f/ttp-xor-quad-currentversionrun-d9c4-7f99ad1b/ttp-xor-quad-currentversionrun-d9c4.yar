rule TTP_XOR_QUAD_CurrentVersionRun_d9c4 {
  strings:
    $key_d9c4 = { 8a ab [2] ae a5 [2] 85 89 [2] ab ab [2] bf b0 [2] b0 aa [2] ae b7 [2] ac b6 [2] b7 b0 [2] ab b7 [2] b7 98 }

  condition:
    any of them
}