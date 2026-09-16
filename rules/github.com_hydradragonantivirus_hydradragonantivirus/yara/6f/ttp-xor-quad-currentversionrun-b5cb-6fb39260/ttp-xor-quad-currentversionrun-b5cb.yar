rule TTP_XOR_QUAD_CurrentVersionRun_b5cb {
  strings:
    $key_b5cb = { e6 a4 [2] c2 aa [2] e9 86 [2] c7 a4 [2] d3 bf [2] dc a5 [2] c2 b8 [2] c0 b9 [2] db bf [2] c7 b8 [2] db 97 }

  condition:
    any of them
}