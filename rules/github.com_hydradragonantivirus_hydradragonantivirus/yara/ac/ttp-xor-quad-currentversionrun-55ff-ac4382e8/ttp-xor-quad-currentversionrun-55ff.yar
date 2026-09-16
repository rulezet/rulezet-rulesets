rule TTP_XOR_QUAD_CurrentVersionRun_55ff {
  strings:
    $key_55ff = { 06 90 [2] 22 9e [2] 09 b2 [2] 27 90 [2] 33 8b [2] 3c 91 [2] 22 8c [2] 20 8d [2] 3b 8b [2] 27 8c [2] 3b a3 }

  condition:
    any of them
}