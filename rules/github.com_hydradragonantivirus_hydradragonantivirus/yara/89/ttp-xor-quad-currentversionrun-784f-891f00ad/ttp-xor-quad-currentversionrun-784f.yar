rule TTP_XOR_QUAD_CurrentVersionRun_784f {
  strings:
    $key_784f = { 2b 20 [2] 0f 2e [2] 24 02 [2] 0a 20 [2] 1e 3b [2] 11 21 [2] 0f 3c [2] 0d 3d [2] 16 3b [2] 0a 3c [2] 16 13 }

  condition:
    any of them
}