rule TTP_XOR_QUAD_CurrentVersionRun_4ce8 {
  strings:
    $key_4ce8 = { 1f 87 [2] 3b 89 [2] 10 a5 [2] 3e 87 [2] 2a 9c [2] 25 86 [2] 3b 9b [2] 39 9a [2] 22 9c [2] 3e 9b [2] 22 b4 }

  condition:
    any of them
}