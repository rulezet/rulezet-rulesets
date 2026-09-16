rule TTP_XOR_QUAD_CurrentVersionRun_3728 {
  strings:
    $key_3728 = { 64 47 [2] 40 49 [2] 6b 65 [2] 45 47 [2] 51 5c [2] 5e 46 [2] 40 5b [2] 42 5a [2] 59 5c [2] 45 5b [2] 59 74 }

  condition:
    any of them
}