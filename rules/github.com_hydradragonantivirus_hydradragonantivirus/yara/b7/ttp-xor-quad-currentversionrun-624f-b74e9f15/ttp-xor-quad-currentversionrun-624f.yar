rule TTP_XOR_QUAD_CurrentVersionRun_624f {
  strings:
    $key_624f = { 31 20 [2] 15 2e [2] 3e 02 [2] 10 20 [2] 04 3b [2] 0b 21 [2] 15 3c [2] 17 3d [2] 0c 3b [2] 10 3c [2] 0c 13 }

  condition:
    any of them
}