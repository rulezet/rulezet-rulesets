rule TTP_XOR_QUAD_CurrentVersionRun_231c {
  strings:
    $key_231c = { 70 73 [2] 54 7d [2] 7f 51 [2] 51 73 [2] 45 68 [2] 4a 72 [2] 54 6f [2] 56 6e [2] 4d 68 [2] 51 6f [2] 4d 40 }

  condition:
    any of them
}