rule TTP_XOR_QUAD_CurrentVersionRun_6e14 {
  strings:
    $key_6e14 = { 3d 7b [2] 19 75 [2] 32 59 [2] 1c 7b [2] 08 60 [2] 07 7a [2] 19 67 [2] 1b 66 [2] 00 60 [2] 1c 67 [2] 00 48 }

  condition:
    any of them
}