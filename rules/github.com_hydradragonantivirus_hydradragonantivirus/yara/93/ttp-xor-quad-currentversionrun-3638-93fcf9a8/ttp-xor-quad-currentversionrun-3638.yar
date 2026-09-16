rule TTP_XOR_QUAD_CurrentVersionRun_3638 {
  strings:
    $key_3638 = { 65 57 [2] 41 59 [2] 6a 75 [2] 44 57 [2] 50 4c [2] 5f 56 [2] 41 4b [2] 43 4a [2] 58 4c [2] 44 4b [2] 58 64 }

  condition:
    any of them
}