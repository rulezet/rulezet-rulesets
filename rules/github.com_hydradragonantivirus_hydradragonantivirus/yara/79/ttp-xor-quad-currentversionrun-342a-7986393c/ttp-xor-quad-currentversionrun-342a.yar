rule TTP_XOR_QUAD_CurrentVersionRun_342a {
  strings:
    $key_342a = { 67 45 [2] 43 4b [2] 68 67 [2] 46 45 [2] 52 5e [2] 5d 44 [2] 43 59 [2] 41 58 [2] 5a 5e [2] 46 59 [2] 5a 76 }

  condition:
    any of them
}