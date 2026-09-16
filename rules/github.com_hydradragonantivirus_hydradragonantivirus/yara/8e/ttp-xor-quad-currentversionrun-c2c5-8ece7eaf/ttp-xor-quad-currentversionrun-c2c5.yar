rule TTP_XOR_QUAD_CurrentVersionRun_c2c5 {
  strings:
    $key_c2c5 = { 91 aa [2] b5 a4 [2] 9e 88 [2] b0 aa [2] a4 b1 [2] ab ab [2] b5 b6 [2] b7 b7 [2] ac b1 [2] b0 b6 [2] ac 99 }

  condition:
    any of them
}