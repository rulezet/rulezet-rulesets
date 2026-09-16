rule TTP_XOR_QUAD_CurrentVersionRun_29ff {
  strings:
    $key_29ff = { 7a 90 [2] 5e 9e [2] 75 b2 [2] 5b 90 [2] 4f 8b [2] 40 91 [2] 5e 8c [2] 5c 8d [2] 47 8b [2] 5b 8c [2] 47 a3 }

  condition:
    any of them
}