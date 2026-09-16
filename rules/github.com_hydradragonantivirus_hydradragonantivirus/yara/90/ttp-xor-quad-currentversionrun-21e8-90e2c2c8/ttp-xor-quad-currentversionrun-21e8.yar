rule TTP_XOR_QUAD_CurrentVersionRun_21e8 {
  strings:
    $key_21e8 = { 72 87 [2] 56 89 [2] 7d a5 [2] 53 87 [2] 47 9c [2] 48 86 [2] 56 9b [2] 54 9a [2] 4f 9c [2] 53 9b [2] 4f b4 }

  condition:
    any of them
}