rule TTP_XOR_QUAD_CurrentVersionRun_6af8 {
  strings:
    $key_6af8 = { 39 97 [2] 1d 99 [2] 36 b5 [2] 18 97 [2] 0c 8c [2] 03 96 [2] 1d 8b [2] 1f 8a [2] 04 8c [2] 18 8b [2] 04 a4 }

  condition:
    any of them
}