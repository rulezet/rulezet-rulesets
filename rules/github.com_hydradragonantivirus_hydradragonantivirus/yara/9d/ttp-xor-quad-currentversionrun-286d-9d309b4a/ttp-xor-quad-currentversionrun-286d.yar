rule TTP_XOR_QUAD_CurrentVersionRun_286d {
  strings:
    $key_286d = { 7b 02 [2] 5f 0c [2] 74 20 [2] 5a 02 [2] 4e 19 [2] 41 03 [2] 5f 1e [2] 5d 1f [2] 46 19 [2] 5a 1e [2] 46 31 }

  condition:
    any of them
}