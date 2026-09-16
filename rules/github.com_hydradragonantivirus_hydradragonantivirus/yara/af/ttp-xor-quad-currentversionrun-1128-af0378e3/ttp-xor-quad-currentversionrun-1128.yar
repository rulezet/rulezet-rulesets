rule TTP_XOR_QUAD_CurrentVersionRun_1128 {
  strings:
    $key_1128 = { 42 47 [2] 66 49 [2] 4d 65 [2] 63 47 [2] 77 5c [2] 78 46 [2] 66 5b [2] 64 5a [2] 7f 5c [2] 63 5b [2] 7f 74 }

  condition:
    any of them
}