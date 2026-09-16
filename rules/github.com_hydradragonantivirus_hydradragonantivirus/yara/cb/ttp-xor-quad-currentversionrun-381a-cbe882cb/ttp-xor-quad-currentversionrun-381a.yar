rule TTP_XOR_QUAD_CurrentVersionRun_381a {
  strings:
    $key_381a = { 6b 75 [2] 4f 7b [2] 64 57 [2] 4a 75 [2] 5e 6e [2] 51 74 [2] 4f 69 [2] 4d 68 [2] 56 6e [2] 4a 69 [2] 56 46 }

  condition:
    any of them
}