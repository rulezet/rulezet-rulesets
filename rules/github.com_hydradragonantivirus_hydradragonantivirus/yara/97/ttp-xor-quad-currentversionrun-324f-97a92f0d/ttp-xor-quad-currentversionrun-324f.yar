rule TTP_XOR_QUAD_CurrentVersionRun_324f {
  strings:
    $key_324f = { 61 20 [2] 45 2e [2] 6e 02 [2] 40 20 [2] 54 3b [2] 5b 21 [2] 45 3c [2] 47 3d [2] 5c 3b [2] 40 3c [2] 5c 13 }

  condition:
    any of them
}