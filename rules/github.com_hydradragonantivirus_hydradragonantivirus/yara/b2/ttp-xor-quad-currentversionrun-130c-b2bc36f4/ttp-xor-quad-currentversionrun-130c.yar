rule TTP_XOR_QUAD_CurrentVersionRun_130c {
  strings:
    $key_130c = { 40 63 [2] 64 6d [2] 4f 41 [2] 61 63 [2] 75 78 [2] 7a 62 [2] 64 7f [2] 66 7e [2] 7d 78 [2] 61 7f [2] 7d 50 }

  condition:
    any of them
}