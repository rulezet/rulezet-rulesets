rule TTP_XOR_QUAD_CurrentVersionRun_3f63 {
  strings:
    $key_3f63 = { 6c 0c [2] 48 02 [2] 63 2e [2] 4d 0c [2] 59 17 [2] 56 0d [2] 48 10 [2] 4a 11 [2] 51 17 [2] 4d 10 [2] 51 3f }

  condition:
    any of them
}