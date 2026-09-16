rule TTP_XOR_QUAD_CurrentVersionRun_202f {
  strings:
    $key_202f = { 73 40 [2] 57 4e [2] 7c 62 [2] 52 40 [2] 46 5b [2] 49 41 [2] 57 5c [2] 55 5d [2] 4e 5b [2] 52 5c [2] 4e 73 }

  condition:
    any of them
}