rule TTP_XOR_QUAD_CurrentVersionRun_6ef8 {
  strings:
    $key_6ef8 = { 3d 97 [2] 19 99 [2] 32 b5 [2] 1c 97 [2] 08 8c [2] 07 96 [2] 19 8b [2] 1b 8a [2] 00 8c [2] 1c 8b [2] 00 a4 }

  condition:
    any of them
}