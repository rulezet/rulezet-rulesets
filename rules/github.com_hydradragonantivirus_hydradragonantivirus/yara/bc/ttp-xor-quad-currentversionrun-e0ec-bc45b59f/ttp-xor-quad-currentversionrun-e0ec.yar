rule TTP_XOR_QUAD_CurrentVersionRun_e0ec {
  strings:
    $key_e0ec = { b3 83 [2] 97 8d [2] bc a1 [2] 92 83 [2] 86 98 [2] 89 82 [2] 97 9f [2] 95 9e [2] 8e 98 [2] 92 9f [2] 8e b0 }

  condition:
    any of them
}