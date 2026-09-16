rule TTP_XOR_QUAD_CurrentVersionRun_92cb {
  strings:
    $key_92cb = { c1 a4 [2] e5 aa [2] ce 86 [2] e0 a4 [2] f4 bf [2] fb a5 [2] e5 b8 [2] e7 b9 [2] fc bf [2] e0 b8 [2] fc 97 }

  condition:
    any of them
}