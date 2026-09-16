rule TTP_XOR_QUAD_CurrentVersionRun_8bcc {
  strings:
    $key_8bcc = { d8 a3 [2] fc ad [2] d7 81 [2] f9 a3 [2] ed b8 [2] e2 a2 [2] fc bf [2] fe be [2] e5 b8 [2] f9 bf [2] e5 90 }

  condition:
    any of them
}