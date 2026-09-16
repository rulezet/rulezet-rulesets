rule TTP_XOR_QUAD_CurrentVersionRun_84cb {
  strings:
    $key_84cb = { d7 a4 [2] f3 aa [2] d8 86 [2] f6 a4 [2] e2 bf [2] ed a5 [2] f3 b8 [2] f1 b9 [2] ea bf [2] f6 b8 [2] ea 97 }

  condition:
    any of them
}