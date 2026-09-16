rule TTP_XOR_QUAD_CurrentVersionRun_3629 {
  strings:
    $key_3629 = { 65 46 [2] 41 48 [2] 6a 64 [2] 44 46 [2] 50 5d [2] 5f 47 [2] 41 5a [2] 43 5b [2] 58 5d [2] 44 5a [2] 58 75 }

  condition:
    any of them
}