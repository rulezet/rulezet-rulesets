rule TTP_XOR_QUAD_CurrentVersionRun_32ff {
  strings:
    $key_32ff = { 61 90 [2] 45 9e [2] 6e b2 [2] 40 90 [2] 54 8b [2] 5b 91 [2] 45 8c [2] 47 8d [2] 5c 8b [2] 40 8c [2] 5c a3 }

  condition:
    any of them
}