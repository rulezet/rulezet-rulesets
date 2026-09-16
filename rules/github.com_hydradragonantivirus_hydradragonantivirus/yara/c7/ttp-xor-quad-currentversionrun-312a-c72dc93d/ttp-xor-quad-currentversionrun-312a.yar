rule TTP_XOR_QUAD_CurrentVersionRun_312a {
  strings:
    $key_312a = { 62 45 [2] 46 4b [2] 6d 67 [2] 43 45 [2] 57 5e [2] 58 44 [2] 46 59 [2] 44 58 [2] 5f 5e [2] 43 59 [2] 5f 76 }

  condition:
    any of them
}