rule TTP_XOR_QUAD_CurrentVersionRun_506a {
  strings:
    $key_506a = { 03 05 [2] 27 0b [2] 0c 27 [2] 22 05 [2] 36 1e [2] 39 04 [2] 27 19 [2] 25 18 [2] 3e 1e [2] 22 19 [2] 3e 36 }

  condition:
    any of them
}