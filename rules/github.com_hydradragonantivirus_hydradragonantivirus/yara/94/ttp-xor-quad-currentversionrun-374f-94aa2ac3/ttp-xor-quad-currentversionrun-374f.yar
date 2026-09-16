rule TTP_XOR_QUAD_CurrentVersionRun_374f {
  strings:
    $key_374f = { 64 20 [2] 40 2e [2] 6b 02 [2] 45 20 [2] 51 3b [2] 5e 21 [2] 40 3c [2] 42 3d [2] 59 3b [2] 45 3c [2] 59 13 }

  condition:
    any of them
}