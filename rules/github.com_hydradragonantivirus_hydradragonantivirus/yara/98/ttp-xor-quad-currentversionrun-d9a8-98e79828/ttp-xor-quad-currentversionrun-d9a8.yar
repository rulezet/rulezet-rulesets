rule TTP_XOR_QUAD_CurrentVersionRun_d9a8 {
  strings:
    $key_d9a8 = { 8a c7 [2] ae c9 [2] 85 e5 [2] ab c7 [2] bf dc [2] b0 c6 [2] ae db [2] ac da [2] b7 dc [2] ab db [2] b7 f4 }

  condition:
    any of them
}