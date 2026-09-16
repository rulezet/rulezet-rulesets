rule TTP_XOR_QUAD_CurrentVersionRun_110b {
  strings:
    $key_110b = { 42 64 [2] 66 6a [2] 4d 46 [2] 63 64 [2] 77 7f [2] 78 65 [2] 66 78 [2] 64 79 [2] 7f 7f [2] 63 78 [2] 7f 57 }

  condition:
    any of them
}