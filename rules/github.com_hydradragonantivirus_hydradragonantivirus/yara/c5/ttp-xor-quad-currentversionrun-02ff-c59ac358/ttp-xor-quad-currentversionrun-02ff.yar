rule TTP_XOR_QUAD_CurrentVersionRun_02ff {
  strings:
    $key_02ff = { 51 90 [2] 75 9e [2] 5e b2 [2] 70 90 [2] 64 8b [2] 6b 91 [2] 75 8c [2] 77 8d [2] 6c 8b [2] 70 8c [2] 6c a3 }

  condition:
    any of them
}