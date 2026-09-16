rule TTP_XOR_QUAD_CurrentVersionRun_4105 {
  strings:
    $key_4105 = { 12 6a [2] 36 64 [2] 1d 48 [2] 33 6a [2] 27 71 [2] 28 6b [2] 36 76 [2] 34 77 [2] 2f 71 [2] 33 76 [2] 2f 59 }

  condition:
    any of them
}