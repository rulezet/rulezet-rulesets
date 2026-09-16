rule TTP_XOR_QUAD_CurrentVersionRun_1b38 {
  strings:
    $key_1b38 = { 48 57 [2] 6c 59 [2] 47 75 [2] 69 57 [2] 7d 4c [2] 72 56 [2] 6c 4b [2] 6e 4a [2] 75 4c [2] 69 4b [2] 75 64 }

  condition:
    any of them
}