rule TTP_XOR_QUAD_CurrentVersionRun_260c {
  strings:
    $key_260c = { 75 63 [2] 51 6d [2] 7a 41 [2] 54 63 [2] 40 78 [2] 4f 62 [2] 51 7f [2] 53 7e [2] 48 78 [2] 54 7f [2] 48 50 }

  condition:
    any of them
}