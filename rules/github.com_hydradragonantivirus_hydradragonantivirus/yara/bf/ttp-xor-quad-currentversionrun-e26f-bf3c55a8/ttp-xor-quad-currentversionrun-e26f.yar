rule TTP_XOR_QUAD_CurrentVersionRun_e26f {
  strings:
    $key_e26f = { b1 00 [2] 95 0e [2] be 22 [2] 90 00 [2] 84 1b [2] 8b 01 [2] 95 1c [2] 97 1d [2] 8c 1b [2] 90 1c [2] 8c 33 }

  condition:
    any of them
}