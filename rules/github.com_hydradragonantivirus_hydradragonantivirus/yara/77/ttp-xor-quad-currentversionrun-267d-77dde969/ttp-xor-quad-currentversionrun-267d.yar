rule TTP_XOR_QUAD_CurrentVersionRun_267d {
  strings:
    $key_267d = { 75 12 [2] 51 1c [2] 7a 30 [2] 54 12 [2] 40 09 [2] 4f 13 [2] 51 0e [2] 53 0f [2] 48 09 [2] 54 0e [2] 48 21 }

  condition:
    any of them
}