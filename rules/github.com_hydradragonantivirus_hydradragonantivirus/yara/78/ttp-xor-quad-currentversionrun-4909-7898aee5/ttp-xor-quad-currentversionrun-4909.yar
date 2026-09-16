rule TTP_XOR_QUAD_CurrentVersionRun_4909 {
  strings:
    $key_4909 = { 1a 66 [2] 3e 68 [2] 15 44 [2] 3b 66 [2] 2f 7d [2] 20 67 [2] 3e 7a [2] 3c 7b [2] 27 7d [2] 3b 7a [2] 27 55 }

  condition:
    any of them
}