rule TTP_XOR_QUAD_CurrentVersionRun_553d {
  strings:
    $key_553d = { 06 52 [2] 22 5c [2] 09 70 [2] 27 52 [2] 33 49 [2] 3c 53 [2] 22 4e [2] 20 4f [2] 3b 49 [2] 27 4e [2] 3b 61 }

  condition:
    any of them
}