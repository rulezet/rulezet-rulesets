rule TTP_XOR_QUAD_CurrentVersionRun_101a {
  strings:
    $key_101a = { 43 75 [2] 67 7b [2] 4c 57 [2] 62 75 [2] 76 6e [2] 79 74 [2] 67 69 [2] 65 68 [2] 7e 6e [2] 62 69 [2] 7e 46 }

  condition:
    any of them
}