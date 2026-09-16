rule TTP_XOR_QUAD_CurrentVersionRun_202d {
  strings:
    $key_202d = { 73 42 [2] 57 4c [2] 7c 60 [2] 52 42 [2] 46 59 [2] 49 43 [2] 57 5e [2] 55 5f [2] 4e 59 [2] 52 5e [2] 4e 71 }

  condition:
    any of them
}