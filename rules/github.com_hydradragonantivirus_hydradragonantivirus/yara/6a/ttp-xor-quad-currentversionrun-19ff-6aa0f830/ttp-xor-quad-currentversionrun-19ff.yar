rule TTP_XOR_QUAD_CurrentVersionRun_19ff {
  strings:
    $key_19ff = { 4a 90 [2] 6e 9e [2] 45 b2 [2] 6b 90 [2] 7f 8b [2] 70 91 [2] 6e 8c [2] 6c 8d [2] 77 8b [2] 6b 8c [2] 77 a3 }

  condition:
    any of them
}