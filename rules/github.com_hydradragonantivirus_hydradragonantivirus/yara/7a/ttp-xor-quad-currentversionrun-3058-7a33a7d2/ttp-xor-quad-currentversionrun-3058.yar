rule TTP_XOR_QUAD_CurrentVersionRun_3058 {
  strings:
    $key_3058 = { 63 37 [2] 47 39 [2] 6c 15 [2] 42 37 [2] 56 2c [2] 59 36 [2] 47 2b [2] 45 2a [2] 5e 2c [2] 42 2b [2] 5e 04 }

  condition:
    any of them
}