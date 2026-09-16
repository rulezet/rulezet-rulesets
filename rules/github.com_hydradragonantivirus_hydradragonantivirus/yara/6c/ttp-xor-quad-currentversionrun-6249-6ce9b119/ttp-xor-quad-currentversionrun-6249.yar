rule TTP_XOR_QUAD_CurrentVersionRun_6249 {
  strings:
    $key_6249 = { 31 26 [2] 15 28 [2] 3e 04 [2] 10 26 [2] 04 3d [2] 0b 27 [2] 15 3a [2] 17 3b [2] 0c 3d [2] 10 3a [2] 0c 15 }

  condition:
    any of them
}