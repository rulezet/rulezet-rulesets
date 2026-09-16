rule TTP_XOR_QUAD_CurrentVersionRun_7e05 {
  strings:
    $key_7e05 = { 2d 6a [2] 09 64 [2] 22 48 [2] 0c 6a [2] 18 71 [2] 17 6b [2] 09 76 [2] 0b 77 [2] 10 71 [2] 0c 76 [2] 10 59 }

  condition:
    any of them
}