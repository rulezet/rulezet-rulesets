rule TTP_XOR_QUAD_CurrentVersionRun_45e5 {
  strings:
    $key_45e5 = { 16 8a [2] 32 84 [2] 19 a8 [2] 37 8a [2] 23 91 [2] 2c 8b [2] 32 96 [2] 30 97 [2] 2b 91 [2] 37 96 [2] 2b b9 }

  condition:
    any of them
}