rule TTP_XOR_QUAD_CurrentVersionRun_9ffe {
  strings:
    $key_9ffe = { cc 91 [2] e8 9f [2] c3 b3 [2] ed 91 [2] f9 8a [2] f6 90 [2] e8 8d [2] ea 8c [2] f1 8a [2] ed 8d [2] f1 a2 }

  condition:
    any of them
}