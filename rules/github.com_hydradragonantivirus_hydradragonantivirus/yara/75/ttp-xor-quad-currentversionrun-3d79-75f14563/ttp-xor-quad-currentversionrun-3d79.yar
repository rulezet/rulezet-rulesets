rule TTP_XOR_QUAD_CurrentVersionRun_3d79 {
  strings:
    $key_3d79 = { 6e 16 [2] 4a 18 [2] 61 34 [2] 4f 16 [2] 5b 0d [2] 54 17 [2] 4a 0a [2] 48 0b [2] 53 0d [2] 4f 0a [2] 53 25 }

  condition:
    any of them
}