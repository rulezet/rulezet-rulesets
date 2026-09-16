rule TTP_XOR_QUAD_CurrentVersionRun_3f4b {
  strings:
    $key_3f4b = { 6c 24 [2] 48 2a [2] 63 06 [2] 4d 24 [2] 59 3f [2] 56 25 [2] 48 38 [2] 4a 39 [2] 51 3f [2] 4d 38 [2] 51 17 }

  condition:
    any of them
}