rule TTP_XOR_QUAD_CurrentVersionRun_3d14 {
  strings:
    $key_3d14 = { 6e 7b [2] 4a 75 [2] 61 59 [2] 4f 7b [2] 5b 60 [2] 54 7a [2] 4a 67 [2] 48 66 [2] 53 60 [2] 4f 67 [2] 53 48 }

  condition:
    any of them
}