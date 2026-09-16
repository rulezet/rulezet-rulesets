rule TTP_XOR_QUAD_CurrentVersionRun_111e {
  strings:
    $key_111e = { 42 71 [2] 66 7f [2] 4d 53 [2] 63 71 [2] 77 6a [2] 78 70 [2] 66 6d [2] 64 6c [2] 7f 6a [2] 63 6d [2] 7f 42 }

  condition:
    any of them
}