rule TTP_XOR_QUAD_CurrentVersionRun_6d29 {
  strings:
    $key_6d29 = { 3e 46 [2] 1a 48 [2] 31 64 [2] 1f 46 [2] 0b 5d [2] 04 47 [2] 1a 5a [2] 18 5b [2] 03 5d [2] 1f 5a [2] 03 75 }

  condition:
    any of them
}