rule TTP_XOR_QUAD_CurrentVersionRun_39ff {
  strings:
    $key_39ff = { 6a 90 [2] 4e 9e [2] 65 b2 [2] 4b 90 [2] 5f 8b [2] 50 91 [2] 4e 8c [2] 4c 8d [2] 57 8b [2] 4b 8c [2] 57 a3 }

  condition:
    any of them
}