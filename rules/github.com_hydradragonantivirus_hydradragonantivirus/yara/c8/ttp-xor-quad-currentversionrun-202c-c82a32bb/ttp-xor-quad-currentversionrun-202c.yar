rule TTP_XOR_QUAD_CurrentVersionRun_202c {
  strings:
    $key_202c = { 73 43 [2] 57 4d [2] 7c 61 [2] 52 43 [2] 46 58 [2] 49 42 [2] 57 5f [2] 55 5e [2] 4e 58 [2] 52 5f [2] 4e 70 }

  condition:
    any of them
}