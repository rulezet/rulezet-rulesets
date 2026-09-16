rule TTP_XOR_QUAD_CurrentVersionRun_512a {
  strings:
    $key_512a = { 02 45 [2] 26 4b [2] 0d 67 [2] 23 45 [2] 37 5e [2] 38 44 [2] 26 59 [2] 24 58 [2] 3f 5e [2] 23 59 [2] 3f 76 }

  condition:
    any of them
}