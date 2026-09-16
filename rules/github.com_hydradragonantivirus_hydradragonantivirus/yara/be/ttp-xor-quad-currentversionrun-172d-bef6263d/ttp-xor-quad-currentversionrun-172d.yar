rule TTP_XOR_QUAD_CurrentVersionRun_172d {
  strings:
    $key_172d = { 44 42 [2] 60 4c [2] 4b 60 [2] 65 42 [2] 71 59 [2] 7e 43 [2] 60 5e [2] 62 5f [2] 79 59 [2] 65 5e [2] 79 71 }

  condition:
    any of them
}