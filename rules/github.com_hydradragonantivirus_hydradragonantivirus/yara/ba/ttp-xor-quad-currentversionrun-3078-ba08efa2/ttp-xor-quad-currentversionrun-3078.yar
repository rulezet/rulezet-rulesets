rule TTP_XOR_QUAD_CurrentVersionRun_3078 {
  strings:
    $key_3078 = { 63 17 [2] 47 19 [2] 6c 35 [2] 42 17 [2] 56 0c [2] 59 16 [2] 47 0b [2] 45 0a [2] 5e 0c [2] 42 0b [2] 5e 24 }

  condition:
    any of them
}