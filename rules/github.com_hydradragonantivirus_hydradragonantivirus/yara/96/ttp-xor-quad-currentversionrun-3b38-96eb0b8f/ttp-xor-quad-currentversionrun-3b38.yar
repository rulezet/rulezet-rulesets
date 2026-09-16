rule TTP_XOR_QUAD_CurrentVersionRun_3b38 {
  strings:
    $key_3b38 = { 68 57 [2] 4c 59 [2] 67 75 [2] 49 57 [2] 5d 4c [2] 52 56 [2] 4c 4b [2] 4e 4a [2] 55 4c [2] 49 4b [2] 55 64 }

  condition:
    any of them
}