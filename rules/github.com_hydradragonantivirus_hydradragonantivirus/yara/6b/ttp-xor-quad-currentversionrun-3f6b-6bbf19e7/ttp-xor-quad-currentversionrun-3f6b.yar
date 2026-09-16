rule TTP_XOR_QUAD_CurrentVersionRun_3f6b {
  strings:
    $key_3f6b = { 6c 04 [2] 48 0a [2] 63 26 [2] 4d 04 [2] 59 1f [2] 56 05 [2] 48 18 [2] 4a 19 [2] 51 1f [2] 4d 18 [2] 51 37 }

  condition:
    any of them
}