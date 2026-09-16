rule TTP_XOR_QUAD_CurrentVersionRun_200c {
  strings:
    $key_200c = { 73 63 [2] 57 6d [2] 7c 41 [2] 52 63 [2] 46 78 [2] 49 62 [2] 57 7f [2] 55 7e [2] 4e 78 [2] 52 7f [2] 4e 50 }

  condition:
    any of them
}