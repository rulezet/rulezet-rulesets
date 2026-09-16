rule TTP_XOR_QUAD_CurrentVersionRun_46ff {
  strings:
    $key_46ff = { 15 90 [2] 31 9e [2] 1a b2 [2] 34 90 [2] 20 8b [2] 2f 91 [2] 31 8c [2] 33 8d [2] 28 8b [2] 34 8c [2] 28 a3 }

  condition:
    any of them
}