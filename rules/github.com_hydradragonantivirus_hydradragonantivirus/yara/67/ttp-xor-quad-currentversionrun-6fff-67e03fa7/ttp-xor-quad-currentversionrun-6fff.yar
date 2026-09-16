rule TTP_XOR_QUAD_CurrentVersionRun_6fff {
  strings:
    $key_6fff = { 3c 90 [2] 18 9e [2] 33 b2 [2] 1d 90 [2] 09 8b [2] 06 91 [2] 18 8c [2] 1a 8d [2] 01 8b [2] 1d 8c [2] 01 a3 }

  condition:
    any of them
}