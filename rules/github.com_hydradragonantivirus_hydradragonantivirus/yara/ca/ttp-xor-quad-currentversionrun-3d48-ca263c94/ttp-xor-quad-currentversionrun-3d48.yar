rule TTP_XOR_QUAD_CurrentVersionRun_3d48 {
  strings:
    $key_3d48 = { 6e 27 [2] 4a 29 [2] 61 05 [2] 4f 27 [2] 5b 3c [2] 54 26 [2] 4a 3b [2] 48 3a [2] 53 3c [2] 4f 3b [2] 53 14 }

  condition:
    any of them
}