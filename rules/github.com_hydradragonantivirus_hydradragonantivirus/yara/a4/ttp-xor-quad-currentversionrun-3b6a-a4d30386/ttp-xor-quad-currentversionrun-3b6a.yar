rule TTP_XOR_QUAD_CurrentVersionRun_3b6a {
  strings:
    $key_3b6a = { 68 05 [2] 4c 0b [2] 67 27 [2] 49 05 [2] 5d 1e [2] 52 04 [2] 4c 19 [2] 4e 18 [2] 55 1e [2] 49 19 [2] 55 36 }

  condition:
    any of them
}