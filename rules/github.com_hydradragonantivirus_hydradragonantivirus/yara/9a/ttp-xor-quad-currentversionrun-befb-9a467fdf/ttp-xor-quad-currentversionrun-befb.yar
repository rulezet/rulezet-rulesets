rule TTP_XOR_QUAD_CurrentVersionRun_befb {
  strings:
    $key_befb = { ed 94 [2] c9 9a [2] e2 b6 [2] cc 94 [2] d8 8f [2] d7 95 [2] c9 88 [2] cb 89 [2] d0 8f [2] cc 88 [2] d0 a7 }

  condition:
    any of them
}