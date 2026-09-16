rule TTP_XOR_QUAD_CurrentVersionRun_6a09 {
  strings:
    $key_6a09 = { 39 66 [2] 1d 68 [2] 36 44 [2] 18 66 [2] 0c 7d [2] 03 67 [2] 1d 7a [2] 1f 7b [2] 04 7d [2] 18 7a [2] 04 55 }

  condition:
    any of them
}