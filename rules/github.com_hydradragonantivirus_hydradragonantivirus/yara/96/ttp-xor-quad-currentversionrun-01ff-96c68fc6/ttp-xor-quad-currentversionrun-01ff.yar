rule TTP_XOR_QUAD_CurrentVersionRun_01ff {
  strings:
    $key_01ff = { 52 90 [2] 76 9e [2] 5d b2 [2] 73 90 [2] 67 8b [2] 68 91 [2] 76 8c [2] 74 8d [2] 6f 8b [2] 73 8c [2] 6f a3 }

  condition:
    any of them
}