rule TTP_XOR_QUAD_CurrentVersionRun_7fff {
  strings:
    $key_7fff = { 2c 90 [2] 08 9e [2] 23 b2 [2] 0d 90 [2] 19 8b [2] 16 91 [2] 08 8c [2] 0a 8d [2] 11 8b [2] 0d 8c [2] 11 a3 }

  condition:
    any of them
}