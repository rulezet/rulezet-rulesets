rule TTP_XOR_QUAD_CurrentVersionRun_386b {
  strings:
    $key_386b = { 6b 04 [2] 4f 0a [2] 64 26 [2] 4a 04 [2] 5e 1f [2] 51 05 [2] 4f 18 [2] 4d 19 [2] 56 1f [2] 4a 18 [2] 56 37 }

  condition:
    any of them
}