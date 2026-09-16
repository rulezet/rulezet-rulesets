rule TTP_XOR_QUAD_CurrentVersionRun_3f58 {
  strings:
    $key_3f58 = { 6c 37 [2] 48 39 [2] 63 15 [2] 4d 37 [2] 59 2c [2] 56 36 [2] 48 2b [2] 4a 2a [2] 51 2c [2] 4d 2b [2] 51 04 }

  condition:
    any of them
}