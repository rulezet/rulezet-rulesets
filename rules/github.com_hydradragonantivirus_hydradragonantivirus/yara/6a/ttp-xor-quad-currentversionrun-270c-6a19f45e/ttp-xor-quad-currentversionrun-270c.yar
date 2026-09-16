rule TTP_XOR_QUAD_CurrentVersionRun_270c {
  strings:
    $key_270c = { 74 63 [2] 50 6d [2] 7b 41 [2] 55 63 [2] 41 78 [2] 4e 62 [2] 50 7f [2] 52 7e [2] 49 78 [2] 55 7f [2] 49 50 }

  condition:
    any of them
}