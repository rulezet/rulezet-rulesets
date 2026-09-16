rule TTP_XOR_QUAD_CurrentVersionRun_5fff {
  strings:
    $key_5fff = { 0c 90 [2] 28 9e [2] 03 b2 [2] 2d 90 [2] 39 8b [2] 36 91 [2] 28 8c [2] 2a 8d [2] 31 8b [2] 2d 8c [2] 31 a3 }

  condition:
    any of them
}