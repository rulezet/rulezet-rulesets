rule TTP_XOR_QUAD_CurrentVersionRun_512c {
  strings:
    $key_512c = { 02 43 [2] 26 4d [2] 0d 61 [2] 23 43 [2] 37 58 [2] 38 42 [2] 26 5f [2] 24 5e [2] 3f 58 [2] 23 5f [2] 3f 70 }

  condition:
    any of them
}