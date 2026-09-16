rule TTP_XOR_QUAD_CurrentVersionRun_234a {
  strings:
    $key_234a = { 70 25 [2] 54 2b [2] 7f 07 [2] 51 25 [2] 45 3e [2] 4a 24 [2] 54 39 [2] 56 38 [2] 4d 3e [2] 51 39 [2] 4d 16 }

  condition:
    any of them
}