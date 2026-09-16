rule TTP_XOR_QUAD_CurrentVersionRun_7e19 {
  strings:
    $key_7e19 = { 2d 76 [2] 09 78 [2] 22 54 [2] 0c 76 [2] 18 6d [2] 17 77 [2] 09 6a [2] 0b 6b [2] 10 6d [2] 0c 6a [2] 10 45 }

  condition:
    any of them
}