rule TTP_XOR_QUAD_CurrentVersionRun_233a {
  strings:
    $key_233a = { 70 55 [2] 54 5b [2] 7f 77 [2] 51 55 [2] 45 4e [2] 4a 54 [2] 54 49 [2] 56 48 [2] 4d 4e [2] 51 49 [2] 4d 66 }

  condition:
    any of them
}