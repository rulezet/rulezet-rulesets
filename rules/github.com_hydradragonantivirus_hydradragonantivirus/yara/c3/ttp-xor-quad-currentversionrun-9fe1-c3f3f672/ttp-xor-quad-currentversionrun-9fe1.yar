rule TTP_XOR_QUAD_CurrentVersionRun_9fe1 {
  strings:
    $key_9fe1 = { cc 8e [2] e8 80 [2] c3 ac [2] ed 8e [2] f9 95 [2] f6 8f [2] e8 92 [2] ea 93 [2] f1 95 [2] ed 92 [2] f1 bd }

  condition:
    any of them
}