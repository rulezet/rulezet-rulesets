rule TTP_XOR_QUAD_CurrentVersionRun_37ff {
  strings:
    $key_37ff = { 64 90 [2] 40 9e [2] 6b b2 [2] 45 90 [2] 51 8b [2] 5e 91 [2] 40 8c [2] 42 8d [2] 59 8b [2] 45 8c [2] 59 a3 }

  condition:
    any of them
}