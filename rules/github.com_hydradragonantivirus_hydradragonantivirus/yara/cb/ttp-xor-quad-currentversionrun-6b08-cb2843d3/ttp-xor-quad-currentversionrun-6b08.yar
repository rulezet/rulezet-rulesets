rule TTP_XOR_QUAD_CurrentVersionRun_6b08 {
  strings:
    $key_6b08 = { 38 67 [2] 1c 69 [2] 37 45 [2] 19 67 [2] 0d 7c [2] 02 66 [2] 1c 7b [2] 1e 7a [2] 05 7c [2] 19 7b [2] 05 54 }

  condition:
    any of them
}