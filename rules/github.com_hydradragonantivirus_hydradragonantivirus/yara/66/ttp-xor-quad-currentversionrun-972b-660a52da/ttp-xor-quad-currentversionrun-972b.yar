rule TTP_XOR_QUAD_CurrentVersionRun_972b {
  strings:
    $key_972b = { c4 44 [2] e0 4a [2] cb 66 [2] e5 44 [2] f1 5f [2] fe 45 [2] e0 58 [2] e2 59 [2] f9 5f [2] e5 58 [2] f9 77 }

  condition:
    any of them
}