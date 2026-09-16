rule TTP_XOR_QUAD_CurrentVersionRun_1129 {
  strings:
    $key_1129 = { 42 46 [2] 66 48 [2] 4d 64 [2] 63 46 [2] 77 5d [2] 78 47 [2] 66 5a [2] 64 5b [2] 7f 5d [2] 63 5a [2] 7f 75 }

  condition:
    any of them
}