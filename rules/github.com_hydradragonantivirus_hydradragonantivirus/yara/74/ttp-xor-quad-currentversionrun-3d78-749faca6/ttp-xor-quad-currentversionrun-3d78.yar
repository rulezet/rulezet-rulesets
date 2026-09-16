rule TTP_XOR_QUAD_CurrentVersionRun_3d78 {
  strings:
    $key_3d78 = { 6e 17 [2] 4a 19 [2] 61 35 [2] 4f 17 [2] 5b 0c [2] 54 16 [2] 4a 0b [2] 48 0a [2] 53 0c [2] 4f 0b [2] 53 24 }

  condition:
    any of them
}