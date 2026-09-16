rule TTP_XOR_QUAD_CurrentVersionRun_3a2d {
  strings:
    $key_3a2d = { 69 42 [2] 4d 4c [2] 66 60 [2] 48 42 [2] 5c 59 [2] 53 43 [2] 4d 5e [2] 4f 5f [2] 54 59 [2] 48 5e [2] 54 71 }

  condition:
    any of them
}