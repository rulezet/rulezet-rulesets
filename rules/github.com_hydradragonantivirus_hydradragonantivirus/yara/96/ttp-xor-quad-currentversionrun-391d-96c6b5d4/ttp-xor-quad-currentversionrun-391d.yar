rule TTP_XOR_QUAD_CurrentVersionRun_391d {
  strings:
    $key_391d = { 6a 72 [2] 4e 7c [2] 65 50 [2] 4b 72 [2] 5f 69 [2] 50 73 [2] 4e 6e [2] 4c 6f [2] 57 69 [2] 4b 6e [2] 57 41 }

  condition:
    any of them
}