rule TTP_XOR_QUAD_CurrentVersionRun_724f {
  strings:
    $key_724f = { 21 20 [2] 05 2e [2] 2e 02 [2] 00 20 [2] 14 3b [2] 1b 21 [2] 05 3c [2] 07 3d [2] 1c 3b [2] 00 3c [2] 1c 13 }

  condition:
    any of them
}