rule TTP_XOR_QUAD_CurrentVersionRun_972f {
  strings:
    $key_972f = { c4 40 [2] e0 4e [2] cb 62 [2] e5 40 [2] f1 5b [2] fe 41 [2] e0 5c [2] e2 5d [2] f9 5b [2] e5 5c [2] f9 73 }

  condition:
    any of them
}