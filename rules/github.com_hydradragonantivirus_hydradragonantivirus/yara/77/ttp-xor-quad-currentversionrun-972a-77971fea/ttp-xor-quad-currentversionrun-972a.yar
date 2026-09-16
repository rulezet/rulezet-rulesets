rule TTP_XOR_QUAD_CurrentVersionRun_972a {
  strings:
    $key_972a = { c4 45 [2] e0 4b [2] cb 67 [2] e5 45 [2] f1 5e [2] fe 44 [2] e0 59 [2] e2 58 [2] f9 5e [2] e5 59 [2] f9 76 }

  condition:
    any of them
}