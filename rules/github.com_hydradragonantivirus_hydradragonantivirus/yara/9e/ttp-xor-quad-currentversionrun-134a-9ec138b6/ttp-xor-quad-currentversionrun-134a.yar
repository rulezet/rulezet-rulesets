rule TTP_XOR_QUAD_CurrentVersionRun_134a {
  strings:
    $key_134a = { 40 25 [2] 64 2b [2] 4f 07 [2] 61 25 [2] 75 3e [2] 7a 24 [2] 64 39 [2] 66 38 [2] 7d 3e [2] 61 39 [2] 7d 16 }

  condition:
    any of them
}