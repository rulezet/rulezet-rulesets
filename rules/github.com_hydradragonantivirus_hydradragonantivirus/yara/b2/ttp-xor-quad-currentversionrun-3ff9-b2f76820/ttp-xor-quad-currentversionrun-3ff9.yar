rule TTP_XOR_QUAD_CurrentVersionRun_3ff9 {
  strings:
    $key_3ff9 = { 6c 96 [2] 48 98 [2] 63 b4 [2] 4d 96 [2] 59 8d [2] 56 97 [2] 48 8a [2] 4a 8b [2] 51 8d [2] 4d 8a [2] 51 a5 }

  condition:
    any of them
}