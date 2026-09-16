rule TTP_XOR_QUAD_CurrentVersionRun_226d {
  strings:
    $key_226d = { 71 02 [2] 55 0c [2] 7e 20 [2] 50 02 [2] 44 19 [2] 4b 03 [2] 55 1e [2] 57 1f [2] 4c 19 [2] 50 1e [2] 4c 31 }

  condition:
    any of them
}