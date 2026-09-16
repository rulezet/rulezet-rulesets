rule TTP_XOR_QUAD_CurrentVersionRun_341b {
  strings:
    $key_341b = { 67 74 [2] 43 7a [2] 68 56 [2] 46 74 [2] 52 6f [2] 5d 75 [2] 43 68 [2] 41 69 [2] 5a 6f [2] 46 68 [2] 5a 47 }

  condition:
    any of them
}