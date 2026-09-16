rule TTP_XOR_QUAD_CurrentVersionRun_3d35 {
  strings:
    $key_3d35 = { 6e 5a [2] 4a 54 [2] 61 78 [2] 4f 5a [2] 5b 41 [2] 54 5b [2] 4a 46 [2] 48 47 [2] 53 41 [2] 4f 46 [2] 53 69 }

  condition:
    any of them
}