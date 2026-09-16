rule TTP_XOR_QUAD_CurrentVersionRun_252d {
  strings:
    $key_252d = { 76 42 [2] 52 4c [2] 79 60 [2] 57 42 [2] 43 59 [2] 4c 43 [2] 52 5e [2] 50 5f [2] 4b 59 [2] 57 5e [2] 4b 71 }

  condition:
    any of them
}