rule TTP_XOR_QUAD_CurrentVersionRun_294f {
  strings:
    $key_294f = { 7a 20 [2] 5e 2e [2] 75 02 [2] 5b 20 [2] 4f 3b [2] 40 21 [2] 5e 3c [2] 5c 3d [2] 47 3b [2] 5b 3c [2] 47 13 }

  condition:
    any of them
}