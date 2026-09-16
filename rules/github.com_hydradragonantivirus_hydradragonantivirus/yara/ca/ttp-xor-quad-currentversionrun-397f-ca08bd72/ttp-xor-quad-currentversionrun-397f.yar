rule TTP_XOR_QUAD_CurrentVersionRun_397f {
  strings:
    $key_397f = { 6a 10 [2] 4e 1e [2] 65 32 [2] 4b 10 [2] 5f 0b [2] 50 11 [2] 4e 0c [2] 4c 0d [2] 57 0b [2] 4b 0c [2] 57 23 }

  condition:
    any of them
}