rule TTP_XOR_QUAD_CurrentVersionRun_e70c {
  strings:
    $key_e70c = { b4 63 [2] 90 6d [2] bb 41 [2] 95 63 [2] 81 78 [2] 8e 62 [2] 90 7f [2] 92 7e [2] 89 78 [2] 95 7f [2] 89 50 }

  condition:
    any of them
}