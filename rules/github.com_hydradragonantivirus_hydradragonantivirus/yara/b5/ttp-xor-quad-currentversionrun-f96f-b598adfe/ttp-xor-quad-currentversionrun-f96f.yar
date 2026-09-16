rule TTP_XOR_QUAD_CurrentVersionRun_f96f {
  strings:
    $key_f96f = { aa 00 [2] 8e 0e [2] a5 22 [2] 8b 00 [2] 9f 1b [2] 90 01 [2] 8e 1c [2] 8c 1d [2] 97 1b [2] 8b 1c [2] 97 33 }

  condition:
    any of them
}