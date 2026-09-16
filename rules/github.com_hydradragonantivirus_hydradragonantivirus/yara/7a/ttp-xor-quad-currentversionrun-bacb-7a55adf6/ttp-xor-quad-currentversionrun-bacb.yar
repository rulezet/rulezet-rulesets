rule TTP_XOR_QUAD_CurrentVersionRun_bacb {
  strings:
    $key_bacb = { e9 a4 [2] cd aa [2] e6 86 [2] c8 a4 [2] dc bf [2] d3 a5 [2] cd b8 [2] cf b9 [2] d4 bf [2] c8 b8 [2] d4 97 }

  condition:
    any of them
}