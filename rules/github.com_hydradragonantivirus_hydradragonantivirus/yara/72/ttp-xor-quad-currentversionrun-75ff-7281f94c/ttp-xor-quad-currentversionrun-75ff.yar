rule TTP_XOR_QUAD_CurrentVersionRun_75ff {
  strings:
    $key_75ff = { 26 90 [2] 02 9e [2] 29 b2 [2] 07 90 [2] 13 8b [2] 1c 91 [2] 02 8c [2] 00 8d [2] 1b 8b [2] 07 8c [2] 1b a3 }

  condition:
    any of them
}