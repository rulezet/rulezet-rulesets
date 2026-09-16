rule TTP_XOR_QUAD_CurrentVersionRun_6fe5 {
  strings:
    $key_6fe5 = { 3c 8a [2] 18 84 [2] 33 a8 [2] 1d 8a [2] 09 91 [2] 06 8b [2] 18 96 [2] 1a 97 [2] 01 91 [2] 1d 96 [2] 01 b9 }

  condition:
    any of them
}