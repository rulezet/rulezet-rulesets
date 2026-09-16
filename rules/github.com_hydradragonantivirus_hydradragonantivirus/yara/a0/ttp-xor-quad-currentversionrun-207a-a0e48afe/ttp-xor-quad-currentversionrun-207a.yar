rule TTP_XOR_QUAD_CurrentVersionRun_207a {
  strings:
    $key_207a = { 73 15 [2] 57 1b [2] 7c 37 [2] 52 15 [2] 46 0e [2] 49 14 [2] 57 09 [2] 55 08 [2] 4e 0e [2] 52 09 [2] 4e 26 }

  condition:
    any of them
}