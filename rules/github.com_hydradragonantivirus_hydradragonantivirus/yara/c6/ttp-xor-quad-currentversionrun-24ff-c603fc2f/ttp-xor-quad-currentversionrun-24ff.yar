rule TTP_XOR_QUAD_CurrentVersionRun_24ff {
  strings:
    $key_24ff = { 77 90 [2] 53 9e [2] 78 b2 [2] 56 90 [2] 42 8b [2] 4d 91 [2] 53 8c [2] 51 8d [2] 4a 8b [2] 56 8c [2] 4a a3 }

  condition:
    any of them
}