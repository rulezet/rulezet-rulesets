rule TTP_XOR_QUAD_CurrentVersionRun_8bcb {
  strings:
    $key_8bcb = { d8 a4 [2] fc aa [2] d7 86 [2] f9 a4 [2] ed bf [2] e2 a5 [2] fc b8 [2] fe b9 [2] e5 bf [2] f9 b8 [2] e5 97 }

  condition:
    any of them
}