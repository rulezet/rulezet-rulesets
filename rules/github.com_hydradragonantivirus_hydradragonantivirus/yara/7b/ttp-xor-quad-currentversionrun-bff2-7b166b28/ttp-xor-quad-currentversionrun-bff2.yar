rule TTP_XOR_QUAD_CurrentVersionRun_bff2 {
  strings:
    $key_bff2 = { ec 9d [2] c8 93 [2] e3 bf [2] cd 9d [2] d9 86 [2] d6 9c [2] c8 81 [2] ca 80 [2] d1 86 [2] cd 81 [2] d1 ae }

  condition:
    any of them
}