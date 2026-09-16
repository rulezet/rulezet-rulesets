rule TTP_XOR_QUAD_CurrentVersionRun_3858 {
  strings:
    $key_3858 = { 6b 37 [2] 4f 39 [2] 64 15 [2] 4a 37 [2] 5e 2c [2] 51 36 [2] 4f 2b [2] 4d 2a [2] 56 2c [2] 4a 2b [2] 56 04 }

  condition:
    any of them
}