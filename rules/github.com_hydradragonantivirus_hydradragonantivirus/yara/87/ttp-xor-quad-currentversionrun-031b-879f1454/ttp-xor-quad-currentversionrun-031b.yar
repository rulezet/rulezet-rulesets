rule TTP_XOR_QUAD_CurrentVersionRun_031b {
  strings:
    $key_031b = { 50 74 [2] 74 7a [2] 5f 56 [2] 71 74 [2] 65 6f [2] 6a 75 [2] 74 68 [2] 76 69 [2] 6d 6f [2] 71 68 [2] 6d 47 }

  condition:
    any of them
}