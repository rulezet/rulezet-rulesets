rule TTP_XOR_QUAD_CurrentVersionRun_26ff {
  strings:
    $key_26ff = { 75 90 [2] 51 9e [2] 7a b2 [2] 54 90 [2] 40 8b [2] 4f 91 [2] 51 8c [2] 53 8d [2] 48 8b [2] 54 8c [2] 48 a3 }

  condition:
    any of them
}