rule TTP_XOR_QUAD_CurrentVersionRun_9ae3 {
  strings:
    $key_9ae3 = { c9 8c [2] ed 82 [2] c6 ae [2] e8 8c [2] fc 97 [2] f3 8d [2] ed 90 [2] ef 91 [2] f4 97 [2] e8 90 [2] f4 bf }

  condition:
    any of them
}