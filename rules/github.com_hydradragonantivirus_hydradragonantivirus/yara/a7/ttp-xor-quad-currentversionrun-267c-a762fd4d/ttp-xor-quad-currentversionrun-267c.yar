rule TTP_XOR_QUAD_CurrentVersionRun_267c {
  strings:
    $key_267c = { 75 13 [2] 51 1d [2] 7a 31 [2] 54 13 [2] 40 08 [2] 4f 12 [2] 51 0f [2] 53 0e [2] 48 08 [2] 54 0f [2] 48 20 }

  condition:
    any of them
}