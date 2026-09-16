rule TTP_XOR_QUAD_CurrentVersionRun_61e7 {
  strings:
    $key_61e7 = { 32 88 [2] 16 86 [2] 3d aa [2] 13 88 [2] 07 93 [2] 08 89 [2] 16 94 [2] 14 95 [2] 0f 93 [2] 13 94 [2] 0f bb }

  condition:
    any of them
}