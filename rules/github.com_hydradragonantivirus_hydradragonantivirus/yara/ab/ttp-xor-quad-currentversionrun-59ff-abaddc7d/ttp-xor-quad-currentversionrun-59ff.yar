rule TTP_XOR_QUAD_CurrentVersionRun_59ff {
  strings:
    $key_59ff = { 0a 90 [2] 2e 9e [2] 05 b2 [2] 2b 90 [2] 3f 8b [2] 30 91 [2] 2e 8c [2] 2c 8d [2] 37 8b [2] 2b 8c [2] 37 a3 }

  condition:
    any of them
}