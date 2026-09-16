rule TTP_XOR_QUAD_CurrentVersionRun_032c {
  strings:
    $key_032c = { 50 43 [2] 74 4d [2] 5f 61 [2] 71 43 [2] 65 58 [2] 6a 42 [2] 74 5f [2] 76 5e [2] 6d 58 [2] 71 5f [2] 6d 70 }

  condition:
    any of them
}