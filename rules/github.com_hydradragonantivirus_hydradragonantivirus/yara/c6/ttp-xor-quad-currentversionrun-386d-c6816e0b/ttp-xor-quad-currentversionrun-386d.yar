rule TTP_XOR_QUAD_CurrentVersionRun_386d {
  strings:
    $key_386d = { 6b 02 [2] 4f 0c [2] 64 20 [2] 4a 02 [2] 5e 19 [2] 51 03 [2] 4f 1e [2] 4d 1f [2] 56 19 [2] 4a 1e [2] 56 31 }

  condition:
    any of them
}