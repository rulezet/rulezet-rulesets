rule TTP_XOR_QUAD_CurrentVersionRun_84f2 {
  strings:
    $key_84f2 = { d7 9d [2] f3 93 [2] d8 bf [2] f6 9d [2] e2 86 [2] ed 9c [2] f3 81 [2] f1 80 [2] ea 86 [2] f6 81 [2] ea ae }

  condition:
    any of them
}