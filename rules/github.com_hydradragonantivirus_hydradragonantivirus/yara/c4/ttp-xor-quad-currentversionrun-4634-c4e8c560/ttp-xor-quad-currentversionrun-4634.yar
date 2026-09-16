rule TTP_XOR_QUAD_CurrentVersionRun_4634 {
  strings:
    $key_4634 = { 15 5b [2] 31 55 [2] 1a 79 [2] 34 5b [2] 20 40 [2] 2f 5a [2] 31 47 [2] 33 46 [2] 28 40 [2] 34 47 [2] 28 68 }

  condition:
    any of them
}