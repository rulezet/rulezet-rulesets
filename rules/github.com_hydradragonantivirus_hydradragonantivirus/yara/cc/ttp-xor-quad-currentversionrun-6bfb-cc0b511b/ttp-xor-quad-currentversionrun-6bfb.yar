rule TTP_XOR_QUAD_CurrentVersionRun_6bfb {
  strings:
    $key_6bfb = { 38 94 [2] 1c 9a [2] 37 b6 [2] 19 94 [2] 0d 8f [2] 02 95 [2] 1c 88 [2] 1e 89 [2] 05 8f [2] 19 88 [2] 05 a7 }

  condition:
    any of them
}