rule TTP_XOR_QUAD_CurrentVersionRun_28ff {
  strings:
    $key_28ff = { 7b 90 [2] 5f 9e [2] 74 b2 [2] 5a 90 [2] 4e 8b [2] 41 91 [2] 5f 8c [2] 5d 8d [2] 46 8b [2] 5a 8c [2] 46 a3 }

  condition:
    any of them
}