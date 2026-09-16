rule TTP_XOR_QUAD_CurrentVersionRun_0865 {
  strings:
    $key_0865 = { 5b 0a [2] 7f 04 [2] 54 28 [2] 7a 0a [2] 6e 11 [2] 61 0b [2] 7f 16 [2] 7d 17 [2] 66 11 [2] 7a 16 [2] 66 39 }

  condition:
    any of them
}