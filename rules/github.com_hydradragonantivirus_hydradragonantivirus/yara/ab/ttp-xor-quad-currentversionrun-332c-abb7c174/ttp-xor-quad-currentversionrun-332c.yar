rule TTP_XOR_QUAD_CurrentVersionRun_332c {
  strings:
    $key_332c = { 60 43 [2] 44 4d [2] 6f 61 [2] 41 43 [2] 55 58 [2] 5a 42 [2] 44 5f [2] 46 5e [2] 5d 58 [2] 41 5f [2] 5d 70 }

  condition:
    any of them
}