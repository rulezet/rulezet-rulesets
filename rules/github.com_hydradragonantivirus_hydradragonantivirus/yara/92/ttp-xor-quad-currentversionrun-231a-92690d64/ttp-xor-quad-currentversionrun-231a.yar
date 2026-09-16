rule TTP_XOR_QUAD_CurrentVersionRun_231a {
  strings:
    $key_231a = { 70 75 [2] 54 7b [2] 7f 57 [2] 51 75 [2] 45 6e [2] 4a 74 [2] 54 69 [2] 56 68 [2] 4d 6e [2] 51 69 [2] 4d 46 }

  condition:
    any of them
}