rule TTP_XOR_QUAD_CurrentVersionRun_232d {
  strings:
    $key_232d = { 70 42 [2] 54 4c [2] 7f 60 [2] 51 42 [2] 45 59 [2] 4a 43 [2] 54 5e [2] 56 5f [2] 4d 59 [2] 51 5e [2] 4d 71 }

  condition:
    any of them
}