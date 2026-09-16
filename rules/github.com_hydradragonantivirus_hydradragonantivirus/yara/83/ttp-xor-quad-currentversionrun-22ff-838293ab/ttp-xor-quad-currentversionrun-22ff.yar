rule TTP_XOR_QUAD_CurrentVersionRun_22ff {
  strings:
    $key_22ff = { 71 90 [2] 55 9e [2] 7e b2 [2] 50 90 [2] 44 8b [2] 4b 91 [2] 55 8c [2] 57 8d [2] 4c 8b [2] 50 8c [2] 4c a3 }

  condition:
    any of them
}