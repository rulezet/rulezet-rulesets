rule TTP_XOR_QUAD_CurrentVersionRun_21ff {
  strings:
    $key_21ff = { 72 90 [2] 56 9e [2] 7d b2 [2] 53 90 [2] 47 8b [2] 48 91 [2] 56 8c [2] 54 8d [2] 4f 8b [2] 53 8c [2] 4f a3 }

  condition:
    any of them
}