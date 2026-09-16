rule TTP_XOR_QUAD_CurrentVersionRun_3f0b {
  strings:
    $key_3f0b = { 6c 64 [2] 48 6a [2] 63 46 [2] 4d 64 [2] 59 7f [2] 56 65 [2] 48 78 [2] 4a 79 [2] 51 7f [2] 4d 78 [2] 51 57 }

  condition:
    any of them
}