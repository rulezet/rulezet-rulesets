rule TTP_XOR_QUAD_CurrentVersionRun_082d {
  strings:
    $key_082d = { 5b 42 [2] 7f 4c [2] 54 60 [2] 7a 42 [2] 6e 59 [2] 61 43 [2] 7f 5e [2] 7d 5f [2] 66 59 [2] 7a 5e [2] 66 71 }

  condition:
    any of them
}