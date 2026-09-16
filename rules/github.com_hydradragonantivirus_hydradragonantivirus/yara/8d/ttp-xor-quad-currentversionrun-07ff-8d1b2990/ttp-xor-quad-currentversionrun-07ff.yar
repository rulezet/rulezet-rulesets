rule TTP_XOR_QUAD_CurrentVersionRun_07ff {
  strings:
    $key_07ff = { 54 90 [2] 70 9e [2] 5b b2 [2] 75 90 [2] 61 8b [2] 6e 91 [2] 70 8c [2] 72 8d [2] 69 8b [2] 75 8c [2] 69 a3 }

  condition:
    any of them
}