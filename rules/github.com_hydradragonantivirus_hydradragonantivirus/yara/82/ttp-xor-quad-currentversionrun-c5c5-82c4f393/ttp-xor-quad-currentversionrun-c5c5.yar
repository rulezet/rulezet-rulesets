rule TTP_XOR_QUAD_CurrentVersionRun_c5c5 {
  strings:
    $key_c5c5 = { 96 aa [2] b2 a4 [2] 99 88 [2] b7 aa [2] a3 b1 [2] ac ab [2] b2 b6 [2] b0 b7 [2] ab b1 [2] b7 b6 [2] ab 99 }

  condition:
    any of them
}