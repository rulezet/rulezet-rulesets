rule TTP_XOR_QUAD_CurrentVersionRun_0d58 {
  strings:
    $key_0d58 = { 5e 37 [2] 7a 39 [2] 51 15 [2] 7f 37 [2] 6b 2c [2] 64 36 [2] 7a 2b [2] 78 2a [2] 63 2c [2] 7f 2b [2] 63 04 }

  condition:
    any of them
}