rule TTP_XOR_QUAD_CurrentVersionRun_4834 {
  strings:
    $key_4834 = { 1b 5b [2] 3f 55 [2] 14 79 [2] 3a 5b [2] 2e 40 [2] 21 5a [2] 3f 47 [2] 3d 46 [2] 26 40 [2] 3a 47 [2] 26 68 }

  condition:
    any of them
}