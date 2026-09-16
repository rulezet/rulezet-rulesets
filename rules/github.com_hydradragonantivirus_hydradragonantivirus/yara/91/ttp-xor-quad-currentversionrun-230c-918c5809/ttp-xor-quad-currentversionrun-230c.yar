rule TTP_XOR_QUAD_CurrentVersionRun_230c {
  strings:
    $key_230c = { 70 63 [2] 54 6d [2] 7f 41 [2] 51 63 [2] 45 78 [2] 4a 62 [2] 54 7f [2] 56 7e [2] 4d 78 [2] 51 7f [2] 4d 50 }

  condition:
    any of them
}