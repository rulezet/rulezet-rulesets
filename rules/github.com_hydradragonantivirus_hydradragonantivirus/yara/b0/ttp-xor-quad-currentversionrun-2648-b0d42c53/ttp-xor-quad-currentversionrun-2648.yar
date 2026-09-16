rule TTP_XOR_QUAD_CurrentVersionRun_2648 {
  strings:
    $key_2648 = { 75 27 [2] 51 29 [2] 7a 05 [2] 54 27 [2] 40 3c [2] 4f 26 [2] 51 3b [2] 53 3a [2] 48 3c [2] 54 3b [2] 48 14 }

  condition:
    any of them
}