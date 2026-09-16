rule TTP_XOR_QUAD_CurrentVersionRun_031e {
  strings:
    $key_031e = { 50 71 [2] 74 7f [2] 5f 53 [2] 71 71 [2] 65 6a [2] 6a 70 [2] 74 6d [2] 76 6c [2] 6d 6a [2] 71 6d [2] 6d 42 }

  condition:
    any of them
}