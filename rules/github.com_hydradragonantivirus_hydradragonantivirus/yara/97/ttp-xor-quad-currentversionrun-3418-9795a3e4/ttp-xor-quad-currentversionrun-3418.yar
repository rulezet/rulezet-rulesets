rule TTP_XOR_QUAD_CurrentVersionRun_3418 {
  strings:
    $key_3418 = { 67 77 [2] 43 79 [2] 68 55 [2] 46 77 [2] 52 6c [2] 5d 76 [2] 43 6b [2] 41 6a [2] 5a 6c [2] 46 6b [2] 5a 44 }

  condition:
    any of them
}