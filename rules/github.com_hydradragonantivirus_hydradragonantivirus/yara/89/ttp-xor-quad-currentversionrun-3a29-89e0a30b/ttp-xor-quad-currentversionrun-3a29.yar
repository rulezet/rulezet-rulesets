rule TTP_XOR_QUAD_CurrentVersionRun_3a29 {
  strings:
    $key_3a29 = { 69 46 [2] 4d 48 [2] 66 64 [2] 48 46 [2] 5c 5d [2] 53 47 [2] 4d 5a [2] 4f 5b [2] 54 5d [2] 48 5a [2] 54 75 }

  condition:
    any of them
}