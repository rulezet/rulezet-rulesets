rule TTP_XOR_QUAD_CurrentVersionRun_1629 {
  strings:
    $key_1629 = { 45 46 [2] 61 48 [2] 4a 64 [2] 64 46 [2] 70 5d [2] 7f 47 [2] 61 5a [2] 63 5b [2] 78 5d [2] 64 5a [2] 78 75 }

  condition:
    any of them
}