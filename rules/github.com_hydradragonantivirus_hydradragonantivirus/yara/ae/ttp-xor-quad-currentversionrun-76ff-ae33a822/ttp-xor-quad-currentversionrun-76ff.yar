rule TTP_XOR_QUAD_CurrentVersionRun_76ff {
  strings:
    $key_76ff = { 25 90 [2] 01 9e [2] 2a b2 [2] 04 90 [2] 10 8b [2] 1f 91 [2] 01 8c [2] 03 8d [2] 18 8b [2] 04 8c [2] 18 a3 }

  condition:
    any of them
}