rule TTP_XOR_QUAD_CurrentVersionRun_121a {
  strings:
    $key_121a = { 41 75 [2] 65 7b [2] 4e 57 [2] 60 75 [2] 74 6e [2] 7b 74 [2] 65 69 [2] 67 68 [2] 7c 6e [2] 60 69 [2] 7c 46 }

  condition:
    any of them
}