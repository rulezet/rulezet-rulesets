rule TTP_XOR_QUAD_CurrentVersionRun_1634 {
  strings:
    $key_1634 = { 45 5b [2] 61 55 [2] 4a 79 [2] 64 5b [2] 70 40 [2] 7f 5a [2] 61 47 [2] 63 46 [2] 78 40 [2] 64 47 [2] 78 68 }

  condition:
    any of them
}