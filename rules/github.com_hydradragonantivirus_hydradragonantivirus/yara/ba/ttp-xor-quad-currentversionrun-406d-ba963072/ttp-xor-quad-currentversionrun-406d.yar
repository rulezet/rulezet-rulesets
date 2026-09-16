rule TTP_XOR_QUAD_CurrentVersionRun_406d {
  strings:
    $key_406d = { 13 02 [2] 37 0c [2] 1c 20 [2] 32 02 [2] 26 19 [2] 29 03 [2] 37 1e [2] 35 1f [2] 2e 19 [2] 32 1e [2] 2e 31 }

  condition:
    any of them
}