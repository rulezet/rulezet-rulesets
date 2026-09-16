rule TTP_XOR_QUAD_CurrentVersionRun_340c {
  strings:
    $key_340c = { 67 63 [2] 43 6d [2] 68 41 [2] 46 63 [2] 52 78 [2] 5d 62 [2] 43 7f [2] 41 7e [2] 5a 78 [2] 46 7f [2] 5a 50 }

  condition:
    any of them
}