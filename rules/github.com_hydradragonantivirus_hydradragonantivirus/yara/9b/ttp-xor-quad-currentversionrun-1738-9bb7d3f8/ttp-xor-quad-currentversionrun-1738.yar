rule TTP_XOR_QUAD_CurrentVersionRun_1738 {
  strings:
    $key_1738 = { 44 57 [2] 60 59 [2] 4b 75 [2] 65 57 [2] 71 4c [2] 7e 56 [2] 60 4b [2] 62 4a [2] 79 4c [2] 65 4b [2] 79 64 }

  condition:
    any of them
}