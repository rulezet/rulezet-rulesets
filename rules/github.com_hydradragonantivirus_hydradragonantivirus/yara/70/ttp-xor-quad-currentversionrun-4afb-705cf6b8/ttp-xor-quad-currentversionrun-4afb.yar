rule TTP_XOR_QUAD_CurrentVersionRun_4afb {
  strings:
    $key_4afb = { 19 94 [2] 3d 9a [2] 16 b6 [2] 38 94 [2] 2c 8f [2] 23 95 [2] 3d 88 [2] 3f 89 [2] 24 8f [2] 38 88 [2] 24 a7 }

  condition:
    any of them
}