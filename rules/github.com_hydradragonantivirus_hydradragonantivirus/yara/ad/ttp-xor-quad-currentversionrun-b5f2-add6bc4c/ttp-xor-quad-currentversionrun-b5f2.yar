rule TTP_XOR_QUAD_CurrentVersionRun_b5f2 {
  strings:
    $key_b5f2 = { e6 9d [2] c2 93 [2] e9 bf [2] c7 9d [2] d3 86 [2] dc 9c [2] c2 81 [2] c0 80 [2] db 86 [2] c7 81 [2] db ae }

  condition:
    any of them
}