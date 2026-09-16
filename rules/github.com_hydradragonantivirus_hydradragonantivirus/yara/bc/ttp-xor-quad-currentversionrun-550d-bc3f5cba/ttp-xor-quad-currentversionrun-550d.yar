rule TTP_XOR_QUAD_CurrentVersionRun_550d {
  strings:
    $key_550d = { 06 62 [2] 22 6c [2] 09 40 [2] 27 62 [2] 33 79 [2] 3c 63 [2] 22 7e [2] 20 7f [2] 3b 79 [2] 27 7e [2] 3b 51 }

  condition:
    any of them
}