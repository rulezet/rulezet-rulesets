rule TTP_XOR_QUAD_CurrentVersionRun_2638 {
  strings:
    $key_2638 = { 75 57 [2] 51 59 [2] 7a 75 [2] 54 57 [2] 40 4c [2] 4f 56 [2] 51 4b [2] 53 4a [2] 48 4c [2] 54 4b [2] 48 64 }

  condition:
    any of them
}