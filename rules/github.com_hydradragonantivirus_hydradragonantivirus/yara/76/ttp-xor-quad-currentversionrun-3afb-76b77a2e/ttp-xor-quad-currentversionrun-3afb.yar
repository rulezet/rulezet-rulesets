rule TTP_XOR_QUAD_CurrentVersionRun_3afb {
  strings:
    $key_3afb = { 69 94 [2] 4d 9a [2] 66 b6 [2] 48 94 [2] 5c 8f [2] 53 95 [2] 4d 88 [2] 4f 89 [2] 54 8f [2] 48 88 [2] 54 a7 }

  condition:
    any of them
}