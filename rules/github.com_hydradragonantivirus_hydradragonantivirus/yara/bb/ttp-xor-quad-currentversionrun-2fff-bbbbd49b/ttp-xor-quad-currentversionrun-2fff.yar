rule TTP_XOR_QUAD_CurrentVersionRun_2fff {
  strings:
    $key_2fff = { 7c 90 [2] 58 9e [2] 73 b2 [2] 5d 90 [2] 49 8b [2] 46 91 [2] 58 8c [2] 5a 8d [2] 41 8b [2] 5d 8c [2] 41 a3 }

  condition:
    any of them
}