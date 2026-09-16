rule TTP_XOR_QUAD_CurrentVersionRun_4039 {
  strings:
    $key_4039 = { 13 56 [2] 37 58 [2] 1c 74 [2] 32 56 [2] 26 4d [2] 29 57 [2] 37 4a [2] 35 4b [2] 2e 4d [2] 32 4a [2] 2e 65 }

  condition:
    any of them
}