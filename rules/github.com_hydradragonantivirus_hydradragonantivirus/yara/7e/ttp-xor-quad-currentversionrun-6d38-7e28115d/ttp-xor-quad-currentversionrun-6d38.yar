rule TTP_XOR_QUAD_CurrentVersionRun_6d38 {
  strings:
    $key_6d38 = { 3e 57 [2] 1a 59 [2] 31 75 [2] 1f 57 [2] 0b 4c [2] 04 56 [2] 1a 4b [2] 18 4a [2] 03 4c [2] 1f 4b [2] 03 64 }

  condition:
    any of them
}