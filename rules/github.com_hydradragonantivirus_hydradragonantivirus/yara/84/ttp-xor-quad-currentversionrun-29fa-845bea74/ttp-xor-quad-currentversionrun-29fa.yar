rule TTP_XOR_QUAD_CurrentVersionRun_29fa {
  strings:
    $key_29fa = { 7a 95 [2] 5e 9b [2] 75 b7 [2] 5b 95 [2] 4f 8e [2] 40 94 [2] 5e 89 [2] 5c 88 [2] 47 8e [2] 5b 89 [2] 47 a6 }

  condition:
    any of them
}