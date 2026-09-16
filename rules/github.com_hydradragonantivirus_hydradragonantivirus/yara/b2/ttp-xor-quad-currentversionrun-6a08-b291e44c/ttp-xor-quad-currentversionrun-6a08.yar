rule TTP_XOR_QUAD_CurrentVersionRun_6a08 {
  strings:
    $key_6a08 = { 39 67 [2] 1d 69 [2] 36 45 [2] 18 67 [2] 0c 7c [2] 03 66 [2] 1d 7b [2] 1f 7a [2] 04 7c [2] 18 7b [2] 04 54 }

  condition:
    any of them
}