rule TTP_XOR_QUAD_CurrentVersionRun_12ff {
  strings:
    $key_12ff = { 41 90 [2] 65 9e [2] 4e b2 [2] 60 90 [2] 74 8b [2] 7b 91 [2] 65 8c [2] 67 8d [2] 7c 8b [2] 60 8c [2] 7c a3 }

  condition:
    any of them
}