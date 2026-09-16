rule TTP_XOR_QUAD_CurrentVersionRun_630c {
  strings:
    $key_630c = { 30 63 [2] 14 6d [2] 3f 41 [2] 11 63 [2] 05 78 [2] 0a 62 [2] 14 7f [2] 16 7e [2] 0d 78 [2] 11 7f [2] 0d 50 }

  condition:
    any of them
}