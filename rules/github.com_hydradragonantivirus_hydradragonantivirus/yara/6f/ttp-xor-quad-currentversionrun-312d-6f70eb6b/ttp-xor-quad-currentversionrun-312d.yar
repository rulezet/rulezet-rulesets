rule TTP_XOR_QUAD_CurrentVersionRun_312d {
  strings:
    $key_312d = { 62 42 [2] 46 4c [2] 6d 60 [2] 43 42 [2] 57 59 [2] 58 43 [2] 46 5e [2] 44 5f [2] 5f 59 [2] 43 5e [2] 5f 71 }

  condition:
    any of them
}