rule TTP_XOR_QUAD_CurrentVersionRun_e329 {
  strings:
    $key_e329 = { b0 46 [2] 94 48 [2] bf 64 [2] 91 46 [2] 85 5d [2] 8a 47 [2] 94 5a [2] 96 5b [2] 8d 5d [2] 91 5a [2] 8d 75 }

  condition:
    any of them
}