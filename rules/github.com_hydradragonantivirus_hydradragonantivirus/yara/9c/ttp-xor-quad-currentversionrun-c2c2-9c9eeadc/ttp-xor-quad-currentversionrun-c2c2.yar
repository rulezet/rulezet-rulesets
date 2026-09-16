rule TTP_XOR_QUAD_CurrentVersionRun_c2c2 {
  strings:
    $key_c2c2 = { 91 ad [2] b5 a3 [2] 9e 8f [2] b0 ad [2] a4 b6 [2] ab ac [2] b5 b1 [2] b7 b0 [2] ac b6 [2] b0 b1 [2] ac 9e }

  condition:
    any of them
}