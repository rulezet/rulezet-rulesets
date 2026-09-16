rule TTP_XOR_QUAD_CurrentVersionRun_baf2 {
  strings:
    $key_baf2 = { e9 9d [2] cd 93 [2] e6 bf [2] c8 9d [2] dc 86 [2] d3 9c [2] cd 81 [2] cf 80 [2] d4 86 [2] c8 81 [2] d4 ae }

  condition:
    any of them
}