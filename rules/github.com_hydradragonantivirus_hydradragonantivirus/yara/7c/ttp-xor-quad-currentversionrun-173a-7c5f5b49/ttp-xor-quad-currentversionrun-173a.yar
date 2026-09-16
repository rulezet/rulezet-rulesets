rule TTP_XOR_QUAD_CurrentVersionRun_173a {
  strings:
    $key_173a = { 44 55 [2] 60 5b [2] 4b 77 [2] 65 55 [2] 71 4e [2] 7e 54 [2] 60 49 [2] 62 48 [2] 79 4e [2] 65 49 [2] 79 66 }

  condition:
    any of them
}