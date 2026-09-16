rule TTP_XOR_QUAD_CurrentVersionRun_7b3f {
  strings:
    $key_7b3f = { 28 50 [2] 0c 5e [2] 27 72 [2] 09 50 [2] 1d 4b [2] 12 51 [2] 0c 4c [2] 0e 4d [2] 15 4b [2] 09 4c [2] 15 63 }

  condition:
    any of them
}