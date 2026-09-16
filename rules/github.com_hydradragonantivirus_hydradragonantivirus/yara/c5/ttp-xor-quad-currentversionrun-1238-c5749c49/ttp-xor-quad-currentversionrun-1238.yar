rule TTP_XOR_QUAD_CurrentVersionRun_1238 {
  strings:
    $key_1238 = { 41 57 [2] 65 59 [2] 4e 75 [2] 60 57 [2] 74 4c [2] 7b 56 [2] 65 4b [2] 67 4a [2] 7c 4c [2] 60 4b [2] 7c 64 }

  condition:
    any of them
}