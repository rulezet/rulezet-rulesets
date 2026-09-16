rule TTP_XOR_QUAD_CurrentVersionRun_1639 {
  strings:
    $key_1639 = { 45 56 [2] 61 58 [2] 4a 74 [2] 64 56 [2] 70 4d [2] 7f 57 [2] 61 4a [2] 63 4b [2] 78 4d [2] 64 4a [2] 78 65 }

  condition:
    any of them
}