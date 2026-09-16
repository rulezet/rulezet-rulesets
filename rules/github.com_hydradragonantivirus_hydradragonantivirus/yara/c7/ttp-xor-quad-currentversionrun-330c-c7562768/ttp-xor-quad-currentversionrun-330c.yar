rule TTP_XOR_QUAD_CurrentVersionRun_330c {
  strings:
    $key_330c = { 60 63 [2] 44 6d [2] 6f 41 [2] 41 63 [2] 55 78 [2] 5a 62 [2] 44 7f [2] 46 7e [2] 5d 78 [2] 41 7f [2] 5d 50 }

  condition:
    any of them
}