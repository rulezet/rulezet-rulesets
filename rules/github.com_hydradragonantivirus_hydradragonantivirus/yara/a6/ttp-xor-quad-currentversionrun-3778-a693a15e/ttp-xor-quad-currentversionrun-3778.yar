rule TTP_XOR_QUAD_CurrentVersionRun_3778 {
  strings:
    $key_3778 = { 64 17 [2] 40 19 [2] 6b 35 [2] 45 17 [2] 51 0c [2] 5e 16 [2] 40 0b [2] 42 0a [2] 59 0c [2] 45 0b [2] 59 24 }

  condition:
    any of them
}