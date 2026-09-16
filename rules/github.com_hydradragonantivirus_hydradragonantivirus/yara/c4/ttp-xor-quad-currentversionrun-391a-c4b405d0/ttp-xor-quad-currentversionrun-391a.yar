rule TTP_XOR_QUAD_CurrentVersionRun_391a {
  strings:
    $key_391a = { 6a 75 [2] 4e 7b [2] 65 57 [2] 4b 75 [2] 5f 6e [2] 50 74 [2] 4e 69 [2] 4c 68 [2] 57 6e [2] 4b 69 [2] 57 46 }

  condition:
    any of them
}