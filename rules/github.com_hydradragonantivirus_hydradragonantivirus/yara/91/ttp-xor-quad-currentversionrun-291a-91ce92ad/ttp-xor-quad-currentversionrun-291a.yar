rule TTP_XOR_QUAD_CurrentVersionRun_291a {
  strings:
    $key_291a = { 7a 75 [2] 5e 7b [2] 75 57 [2] 5b 75 [2] 4f 6e [2] 40 74 [2] 5e 69 [2] 5c 68 [2] 47 6e [2] 5b 69 [2] 47 46 }

  condition:
    any of them
}