rule TTP_XOR_QUAD_CurrentVersionRun_386c {
  strings:
    $key_386c = { 6b 03 [2] 4f 0d [2] 64 21 [2] 4a 03 [2] 5e 18 [2] 51 02 [2] 4f 1f [2] 4d 1e [2] 56 18 [2] 4a 1f [2] 56 30 }

  condition:
    any of them
}